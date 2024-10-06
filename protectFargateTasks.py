import boto3
import os
import urllib3
import json
import sys
import re
import base64
from urllib3.util import parse_url, Url
from urllib.parse import urlparse, urlencode
from botocore.exceptions import ClientError

# Load environment variables from .env file
if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()

def get_secret(secret_name):
    """Retrieve Secret from AWS Secrets Manager"""
    # Create a Secrets Manager client
    client = boto3.client('secretsmanager')

    try:
        # Retrieve the secret
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # Handle errors returned by the client
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise Exception("Secrets Manager can't decrypt the protected secret text using the provided KMS key.")
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise Exception("An error occurred on the service side.")
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise Exception("You provided an invalid value for a parameter.")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise Exception("You provided a parameter value that is not valid for the current state of the resource.")
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise Exception("We can't find the resource that you asked for.")
        else:
            raise e

    # Parse the secret response
    if 'SecretString' in get_secret_value_response:
        secret = get_secret_value_response['SecretString']
    else:
        # If the secret is binary, decode it accordingly
        secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    # Return the secret as a dictionary
    return json.loads(secret)


# Import environment variables
PCC_SECRET = os.getenv("PCC_SECRET", "")

# If Secret variable is in place import the secrets to access Prisma Cloud
if PCC_SECRET:
    secret = get_secret(PCC_SECRET)
    PCC_URL = secret["PCC_URL"]
    PCC_USER = secret["PCC_USER"]
    PCC_PASS = secret["PCC_PASS"]
else:
    PCC_URL = os.getenv("PCC_URL", "")
    PCC_USER = os.getenv("PCC_USER", "")
    PCC_PASS = os.getenv("PCC_PASS", "")

PCC_SAN = os.getenv("PCC_SAN", urlparse(PCC_URL).netloc)
FS_MONITOR = os.getenv("FS_MONITOR", "0") in ["1", "True", "true", "yes", "y"]
FIPS_ENABLED = os.getenv("FIPS_ENABLED", "0") in ["1", "True", "true"]
REGISTRY_TYPE = os.getenv("REGISTRY_TYPE", "aws")
CREDENTIAL_ID = os.getenv("CREDENTIAL_ID", "")
VERSION_REGEX = os.getenv("VERSION_REGEX", "[0-9]{2}_[0-9]{2}_[0-9]{3}")
SAMPLE_FILE = os.getenv("SAMPLE_FILE","fargateTask.json")
ROLE_NAME = os.getenv("ROLE_NAME", "FargateDeployMember")
REGIONS = os.getenv("REGIONS", "").split(',')
ACCOUNTS = os.getenv("ACCOUNTS", "").split(',')
UPGRADE = os.getenv("UPGRADE", "1") in ["1", "True", "true", "yes", "y"]

# Removed attributes from task definition JSON
TASK_DEFINITION_REMOVED_ATTRIBUTES = [
    "taskDefinitionArn", 
    "revision",
    "status",
    "requiresAttributes",
    "compatibilities",
    "registeredAt",
    "registeredBy",
    "deregisteredAt"
]

# Creating a PoolManager instance for sending requests.
prisma_cloud_api = urllib3.PoolManager()

# Initialize AWS Organizations and STS clients
org_client = boto3.client('organizations')
sts_client = boto3.client('sts')


def check_connectivity(api_endpoint):
    """Check Connectivity with Prisma Cloud"""
    response = prisma_cloud_api.request("GET", f"{api_endpoint}/api/v1/_ping")
    if response.status == 200:
        print(f"Connection to the endpoint {api_endpoint} succedded.")
    else:
        print(f"Connection to the endpoint {api_endpoint} failed.")
        sys.exit(2)


def get_token(username, password, api_endpoint):
    """Get Access token from Prisma Cloud"""
    headers = {
        "Content-Type": "application/json"
    }

    body = {
        "username": username,
        "password": password
    }

    response = prisma_cloud_api.request("POST", f"{api_endpoint}/api/v1/authenticate", body=json.dumps(body), headers=headers)
    data = json.loads(response.data)
    if response.status == 200:
        return data['token']
    
    print(f"Error while authenticating. Error: {data['err']}")
    sys.exit(5)

def assume_role(account_id, role_name):
    try:
        # Build the role ARN using the account ID and the role name
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        # Assume the role
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='CrossAccountSession'
        )

        # Extract the temporary credentials
        credentials = response['Credentials']
        print(f"Assumed role in account {account_id} successfully")

        # Return the credentials
        return credentials
    except ClientError as e:
        print(f"Failed to assume role in account {account_id}: {e}")
        return None

def add_query_params(url, params):
    """Add query parameters to a URL, removing any parameters with empty values"""
    # Parse the URL
    parsed_url = parse_url(url)

    # Filter out empty parameters
    filtered_params = {k: v for k, v in params.items() if v}

    # Convert query parameters dictionary to query string
    query_string = urlencode(filtered_params)

    # Construct the new URL with the query parameters
    new_url = Url(
        scheme=parsed_url.scheme,
        auth=parsed_url.auth,
        host=parsed_url.host,
        port=parsed_url.port,
        path=parsed_url.path,
        query=query_string,
        fragment=parsed_url.fragment
    )

    return new_url.url


def image_in_registry_scan(image, api_endpoint):
    """Search if an specified image is in the registry scanning results"""
    global headers

    params = {
        "compact": True,
        "search": image
    }
    # Check if image exists in the registry scanning
    registry_scan_url = add_query_params(f"{api_endpoint}/api/v1/registry", params)
    response = prisma_cloud_api.request("GET", registry_scan_url, headers=headers)
    
    if response.status == 401:
        headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token(PCC_USER, PCC_PASS, PCC_URL)}"
        }
        return image_in_registry_scan(image, api_endpoint)

    elif response.status == 200 and response.data:
        return True
    
    return False


def generate_protected_task(
        task_definition,
        api_endpoint,
        console_addr,
        registry_type="aws", 
        registry_credentialID="",
        filesystem_monitoring=False,
        interpreter="",
        cloud_formation=False, 
        defender_image="",
        defender_image_pullsecret=""
):
    """Generate Protected Fargate Task"""
    global headers

    # Remove empty entrypoint
    if 'entryPoint' in task_definition['containerDefinitions'][0]:
        if not task_definition['containerDefinitions'][0]['entryPoint']:
            del task_definition['containerDefinitions'][0]['entryPoint']


    # Remove empty command
    if 'command' in task_definition['containerDefinitions'][0]:
        if not task_definition['containerDefinitions'][0]['command']:
            del task_definition['containerDefinitions'][0]['command']

    extract_entrypoint = not 'entryPoint' in task_definition['containerDefinitions'][0]
    image = task_definition['containerDefinitions'][0]['image']

    # Performing Entrypoint extraction if required
    if extract_entrypoint:
        if image_in_registry_scan(image, api_endpoint):
            registry_type = ""
            registry_credentialID = ""
        
        else:
            if not registry_credentialID and registry_type == "aws":
                print(f"Image {image} not found in registries. Extracting from credentials")
                registry_credentialID = image.split('.')[0]
    
    else:
        registry_type = ""
        registry_credentialID = ""

    params = {
        "consoleaddr": console_addr,
        "cloudFormation": cloud_formation,
        "filesystemMonitoring": filesystem_monitoring,
        "interpreter": interpreter,
        "extractEntrypoint": extract_entrypoint,
        "registryType": registry_type,
        "registryCredentialID": registry_credentialID,
        "defenderImage": defender_image,
        "defenderImagePullSecret": defender_image_pullsecret
    }

    # Generate Protectec task
    generate_protected_task_url = add_query_params(f"{api_endpoint}/api/v1/defenders/fargate.json", params)
    response = prisma_cloud_api.request("POST", generate_protected_task_url, body=json.dumps(task_definition), headers=headers)
    data = json.loads(response.data)

    # A 401 status code means that the token is expired
    if response.status == 401:
        headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token(PCC_USER, PCC_PASS, PCC_URL)}"
        }
        return generate_protected_task(
            task_definition,
            api_endpoint,
            console_addr,
            registry_type, 
            registry_credentialID,
            filesystem_monitoring,
            interpreter,
            cloud_formation, 
            defender_image, 
            defender_image_pullsecret
        )
    
    elif response.status == 200:
        return data
    
    print(f"Error while generating protected task. URL: {generate_protected_task_url}. Error: {data['err']} or entrypoint cannot be extracted. Image: {image}. Status code: {response.status}")
    return None


def get_clusters():
    """Retrieve all ECS clusters"""
    clusters = []
    paginator = ecs_client.get_paginator('list_clusters')
    for page in paginator.paginate():
        clusters.extend(page['clusterArns'])
        
    return clusters


def get_services(cluster_name):
    """Retrieve all services within a specified ECS cluster"""
    services = []
    paginator = ecs_client.get_paginator('list_services')
    for page in paginator.paginate(cluster=cluster_name):
        services.extend(page['serviceArns'])

    return services


def register_task_definition(task_definition):
    """Register a new ECS task definition"""
    # Verify if the parameter 'logConfiguration' inside the container definitions is empty. If is, delete it
    try:
        for container_idx in range(len(task_definition['containerDefinitions'])):
            if 'logConfiguration' in task_definition['containerDefinitions'][container_idx]:
                logConfiguration = task_definition['containerDefinitions'][container_idx]['logConfiguration']
                if not logConfiguration:
                    del task_definition['containerDefinitions'][container_idx]['logConfiguration']

        response = ecs_client.register_task_definition(**task_definition)
        return response['taskDefinition']['taskDefinitionArn']
    
    except Exception as e:
        print(f"Error registering task definition: {e}")
        print(task_definition)
        sys.exit(2)


def update_service(cluster_name, service_name, new_task_definition):
    """Update the ECS service with a new task definition"""
    try:
        response = ecs_client.update_service(
            cluster=cluster_name,
            service=service_name,
            taskDefinition=new_task_definition
        )
        return response
    except Exception as e:
        print(f"Error updating service: {e}")
        return None
    

def protect_fargate_task_definitions(
        cluster_name, 
        service_arns, 
        api_endpoint, 
        console_addr,
        new_defender_image,
        new_install_bundle,
        new_ws_address,
        new_version,
        registry_type="aws", 
        registry_credentialID="", 
        filesystem_monitoring=False,
        interpreter="",
        cloud_formation=False,
        defender_image="",
        defender_image_pullsecret="",
        fips_enabled=False
    ):
    """Protect the FARGATE task definitions with Prisma Cloud Defender"""
    # Import global variable
    global headers

    # Check all existing services
    for service_arn in service_arns:
        service_desc = ecs_client.describe_services(cluster=cluster_name, services=[service_arn])
        if 'services' in service_desc and len(service_desc['services']) > 0:
            for service in service_desc['services']:
                # Verify if the task definition used by the service is used by FARGATE
                is_fargate_task = False
                if 'capacityProviderStrategy' in service:
                    for capacityProviderStrategy in service['capacityProviderStrategy']:
                        if capacityProviderStrategy['capacityProvider'] == 'FARGATE' and capacityProviderStrategy['weight'] > 0:
                            is_fargate_task = True
                
                elif 'launchType' in service:
                    if service['launchType'] == "FARGATE":
                        is_fargate_task = True

                if is_fargate_task:
                    defended_task = False
                    task_definition_arn = service['taskDefinition']
                    task_definition_desc = ecs_client.describe_task_definition(taskDefinition=task_definition_arn)
                    task_definition = task_definition_desc['taskDefinition']

                    # Remove attributes that make conflict when craeting a task definition
                    for attribute in TASK_DEFINITION_REMOVED_ATTRIBUTES:
                        if attribute in task_definition:
                            del task_definition[attribute]

                    defended_task = task_definition['containerDefinitions'][-1]['name'] == 'TwistlockDefender'
                    current_defender_image = task_definition['containerDefinitions'][-1]['image']

                    if not defended_task:
                        print(f"Service {service_arn} does not have defender installed. Installing it")
                        # Protect task and update existing service
                        protected_task = generate_protected_task(
                            task_definition, 
                            api_endpoint, 
                            console_addr,
                            registry_type, 
                            registry_credentialID, 
                            filesystem_monitoring,
                            interpreter,
                            cloud_formation,
                            defender_image,
                            defender_image_pullsecret
                        )
                        if not protected_task:
                            continue

                        new_task_definition_arn = register_task_definition(protected_task)
                        update_service(cluster_name, service_arn, new_task_definition_arn)

                    else:
                        installed_version = re.findall(VERSION_REGEX, current_defender_image)[0].replace("_", ".")
                        print(f"Service {service_arn} already has the defender installed. Installed version: {installed_version}")

                        if new_version != installed_version and UPGRADE:
                            # Update task definition with new defender values
                            print(f"Installed version {installed_version} does not match with the current defender version. Installing version: {new_version}")
                            task_definition['containerDefinitions'][-1]['image'] = new_defender_image
                            sample_protected_task_definition['containerDefinitions'][-1]['environment'][3]['value'] = new_ws_address
                            
                            for container in task_definition['containerDefinitions']:
                                # Change entrypoint begining from old defender versions
                                if container['entryPoint'][0] == "/var/lib/twistlock/fargate/fargate_defender.sh":
                                   container['entryPoint'][0] = "/var/lib/twistlock/fargate/defender" 

                                # Replace environment variables
                                for envvar in container['environment']:
                                    if envvar['name'] == 'INSTALL_BUNDLE': 
                                        envvar['value'] = new_install_bundle
                                    
                                    if envvar['name'] == 'WS_ADDRESS': 
                                        envvar['value'] = new_ws_address
                                
                                    elif envvar['name'] == 'FILESYSTEM_MONITORING': 
                                        envvar['value'] = str(filesystem_monitoring).lower()
                                    
                                    elif envvar['name'] == 'FIPS_ENABLED': 
                                        envvar['value'] = str(fips_enabled).lower()

                            # Update existing service with the changed task
                            new_task_definition_arn = register_task_definition(task_definition)
                            update_service(cluster_name, service_arn, new_task_definition_arn)


if __name__ == "__main__":
    # Check connectivity with Prisma Cloud
    check_connectivity(PCC_URL)

    # Get access token from Prisma Cloud
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {get_token(PCC_USER, PCC_PASS, PCC_URL)}"
    }

    # Extract variables from current defender deployment
    with open(SAMPLE_FILE) as sample_fargate_task:
        sample_task_definition = json.loads(sample_fargate_task.read())
        sample_protected_task_definition = generate_protected_task(
            sample_task_definition, 
            PCC_URL, 
            PCC_SAN
        )
        new_defender_image = sample_protected_task_definition['containerDefinitions'][-1]['image']
        new_install_bundle = sample_protected_task_definition['containerDefinitions'][-1]['environment'][0]['value']
        new_ws_address = sample_protected_task_definition['containerDefinitions'][-1]['environment'][3]['value']
        new_version = re.findall(VERSION_REGEX, new_defender_image)[0].replace("_", ".")
        print(f"Current defender version {new_version}")

    # List all or selected accounts in the organization
    accounts = ACCOUNTS
    if not ACCOUNTS[0]:
        accounts = []
        accounts_details = org_client.list_accounts()['Accounts']
        for account_detail in accounts_details:
            accounts.append(account_detail['Id'])

    for account in accounts:
        print(f"Attempting to assume role in account Id {account}")

        # Assume the role in the account
        credentials = assume_role(account, ROLE_NAME)

        if credentials:
            # Create a new session with the assumed role credentials:
            assumed_session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )

            # Use the EC2 client to list available regions, as ECS operates in all EC2 regions
            ec2_client = assumed_session.client('ec2')

            # Get the list of all available or selected regions
            regions = REGIONS
            if not REGIONS[0]:
                regions_details = ec2_client.describe_regions()
                regions = [region['RegionName'] for region in regions_details['Regions']]
                 
            for region in regions:
                try:
                    # Set the region to use as environment variable
                    os.environ["AWS_DEFAULT_REGION"] = region
                    print(f"Accessing region {region}")

                    # Initialize the Boto3 client for ECS
                    ecs_client = assumed_session.client('ecs')

                    # Get list of clusters
                    clusters = get_clusters()


                    # Loop through each cluster and get services and task definitions
                    for cluster in clusters:
                        print(f"Accessing cluster: {cluster}")
                        services = get_services(cluster)
                        protect_fargate_task_definitions(
                            cluster, 
                            services, 
                            PCC_URL, 
                            PCC_SAN,
                            new_defender_image,
                            new_install_bundle,
                            new_ws_address,
                            new_version,
                            REGISTRY_TYPE,
                            CREDENTIAL_ID,
                            FS_MONITOR
                        )
                except ClientError as e:
                    print(f"Failed in request: {e}")