import boto3
import os
import json
import sys
import re

from base64 import b64decode, b64encode
from prismaapi import PrismaAPI
from urllib3 import PoolManager
from urllib.parse import urlparse, urlencode
from botocore.exceptions import ClientError

# Load environment variables from .env file
if os.path.exists(".env"):
    from dotenv import load_dotenv
    load_dotenv()


def get_secret(secret_name):
    """Retrieve Secret from AWS Secrets Manager"""
    # Create a Secrets Manager client
    client = boto3.client("secretsmanager")

    try:
        # Retrieve the secret
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        # Handle errors returned by the client
        if e.response["Error"]["Code"] == "DecryptionFailureException":
            raise Exception("Secrets Manager can't decrypt the protected secret text using the provided KMS key.")
        elif e.response["Error"]["Code"] == "InternalServiceErrorException":
            raise Exception("An error occurred on the service side.")
        elif e.response["Error"]["Code"] == "InvalidParameterException":
            raise Exception("You provided an invalid value for a parameter.")
        elif e.response["Error"]["Code"] == "InvalidRequestException":
            raise Exception("You provided a parameter value that is not valid for the current state of the resource.")
        elif e.response["Error"]["Code"] == "ResourceNotFoundException":
            raise Exception("We can't find the resource that you asked for.")
        else:
            raise e

    # Parse the secret response
    if "SecretString" in get_secret_value_response:
        secret = get_secret_value_response["SecretString"]
    else:
        # If the secret is binary, decode it accordingly
        secret = b64decode(get_secret_value_response["SecretBinary"])

    # Return the secret as a dictionary
    return json.loads(secret)


# Import secrets
PCC_SECRET = os.getenv("PCC_SECRET")
secret = {} if not PCC_SECRET else get_secret(PCC_SECRET)
PCC_URL = os.getenv("PCC_URL") if not "PCC_URL" in secret else secret["PCC_URL"]
PCC_USER = os.getenv("PCC_USER") if not "PCC_USER" in secret else secret["PCC_USER"]
PCC_PASS = os.getenv("PCC_PASS") if not "PCC_PASS" in secret else secret["PCC_PASS"]
DOCKER_USER = os.getenv("DOCKER_USER") if not "DOCKER_USER" in secret else secret["DOCKER_USER"]
DOCKER_PASS = os.getenv("DOCKER_PASS") if not "DOCKER_PASS" in secret else secret["DOCKER_PASS"]

# Import additional environment variables
PCC_SAN = os.getenv("PCC_SAN", urlparse(PCC_URL).netloc)
FS_MONITOR = os.getenv("FS_MONITOR", "0") in ["1", "True", "true", "yes", "y"]
FIPS_ENABLED = os.getenv("FIPS_ENABLED", "0") in ["1", "True", "true"]
REGISTRY_TYPE = os.getenv("REGISTRY_TYPE", "aws")
CREDENTIAL_ID = os.getenv("CREDENTIAL_ID", "")
ROLE_NAME = os.getenv("ROLE_NAME", "FargateDeployMember")
REGIONS = os.getenv("REGIONS", "").split(",")
ACCOUNTS = os.getenv("ACCOUNTS", "").split(",")
CLUSTERS = os.getenv("CLUSTERS", "").split(",")
UPGRADE = os.getenv("UPGRADE", "1") in ["1", "True", "true", "yes", "y"]
DEPLOYMENT_MODE = os.getenv("DEPLOYMENT_MODE", "ORG") == "ORG"
WAAS_PORT = int(os.getenv("WAAS_PORT", "0"))
DEBUG = os.getenv("DEBUG", "false") == "true"

# Mandatory values
SAMPLE_FILE = "fargateTask.json"
VERSION_REGEX = "[0-9]{2}_[0-9]{2}_[0-9]{3}"

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
http = PoolManager()

# Initialize AWS Organizations and STS clients
if DEPLOYMENT_MODE:
    org_client = boto3.client("organizations")

sts_client = boto3.client("sts")

def image_entrypoint_cmd(repository: str, registry="registry-1.docker.io", tag="latest", architecture="amd64", docker_user = None, docker_pass = None):
    """
    Fetches and prints the Entrypoint and Cmd of a public Docker image
    using the Docker Registry V2 API with urllib3.

    Args:
        repository (str): The name of the repository (e.g., "library/ubuntu").
        tag (str): The image tag (e.g., "latest").
        architecture (str): The desired CPU architecture (e.g., "amd64").
    """
    # --- Step 1: replace the repository if does not contain / ---
    if "/" not in repository:
        repository = f"library/{repository}"
    
    # --- Step 2: Get Authentication Token ---
    print(f"1. Requesting auth token for {repository}...")
    token = ""
    if docker_user and docker_pass:
        auth = b64encode(f"{docker_user}:{docker_pass}".encode()).decode()
        auth_header = {"Authorization": f"Basic {auth}"}

    elif registry == "registry-1.docker.io":
        # Get Auth Token from Docker Hub
        auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository}:pull"
        response = http.request("GET", auth_url)
        if response.status != 200:
            print(f"Error: Failed to get auth token. Status: {response.status}")
            return

        token = json.loads(response.data.decode("utf-8"))["token"]
        auth_header = {"Authorization": f"Bearer {token}"}

    elif registry == "public.ecr.aws":
        # Get Auth Token from Public ECR registry
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        ecr_client = boto3.client("ecr-public")
        response = ecr_client.get_authorization_token()
        token = response["authorizationData"]["authorizationToken"]
        auth_header = {"Authorization": f"Bearer {token}"}
    
    else:
        print(f"{registry} not supported yet to extect entrypoint")
        return

    
    # Common headers for manifest requests
    manifest_headers = {
        "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json",
        **auth_header
    }

    # --- Step 3: Fetch the Manifest List ---
    print(f"2. Fetching manifest list for tag '{tag}'...")
    manifest_url = f"https://{registry}/v2/{repository}/manifests/{tag}"
    
    response = http.request("GET", manifest_url, headers=manifest_headers)
    if response.status == 401 and docker_pass and docker_user:
        # Attempt to use DockerHub public registry
        image_entrypoint_cmd(repository=repository, tag=tag)

    elif response.status != 200:
        print(f"Error: Failed to fetch manifest. Status: {response.status}")
        return
        
    manifest_data = json.loads(response.data.decode("utf-8"))

    # --- Step 4: Select the Architecture ---
    image_manifest_digest = ""
    # Check if this is a manifest list (multi-architecture)
    if "manifests" in manifest_data:
        print(f"3. Manifest list found. Searching for '{architecture}' architecture...")
        for manifest in manifest_data["manifests"]:
            if manifest.get("platform", {}).get("architecture") == architecture:
                image_manifest_digest = manifest["digest"]
                break
        if not image_manifest_digest:
            print(f"Error: Could not find manifest for architecture '{architecture}'")
            return
    # If not a list, it"s a single-architecture manifest already
    else:
        print("3. Single architecture manifest found.")
        # We need the digest of the config, not the manifest itself yet.
        # This will be handled in the next step.
        image_manifest_digest = response.headers.get("Docker-Content-Digest")


    # --- Step 5: Fetch the Architecture-Specific Manifest (if needed) ---
    # This step is only necessary if we started with a manifest list.
    if "manifests" in manifest_data:
        print(f"4. Fetching architecture-specific manifest using digest {image_manifest_digest[:15]}...")
        image_manifest_url = f"https://{registry}/v2/{repository}/manifests/{image_manifest_digest}"
        response = http.request("GET", image_manifest_url, headers=manifest_headers)
        if response.status != 200:
            print(f"Error: Failed to fetch image manifest. Status: {response.status}")
            return
        image_manifest = json.loads(response.data.decode("utf-8"))
    else:
        # If it was a single manifest to begin with, we already have it.
        image_manifest = manifest_data

    config_digest = image_manifest["config"]["digest"]

    # --- Step 6: Fetch the Configuration Blob ---
    print(f"5. Fetching config blob with digest {config_digest[:15]}...")
    config_url = f"https://{registry}/v2/{repository}/blobs/{config_digest}"
    
    response = http.request("GET", config_url, headers=auth_header)
    if response.status != 200:
        print(f"Error: Failed to fetch config blob. Status: {response.status}")
        return
    
    config_data = json.loads(response.data.decode("utf-8"))

    # --- Step 7: Extract and Print Entrypoint and Cmd ---
    entrypoint = config_data.get("config", {}).get("Entrypoint")
    cmd = config_data.get("config", {}).get("Cmd")

    print("\n--- Result ---")
    print(f"Image: {repository}:{tag} ({architecture})")
    print(f"Entrypoint: {entrypoint}")
    print(f"Cmd: {cmd}")
    print("--------------\n")
    return {"entryPoint": entrypoint, "command": cmd}


def parse_docker_image(image_name):
    """
    Manually parses a Docker image name to extract its components.

    Args:
        image_name: The full name of the Docker image.

    Returns:
        A dictionary containing the registry, repository, and tag.
    """
    # Default values
    registry = "registry-1.docker.io"
    tag = "latest"

    # Handle digest
    if "@" in image_name:
        name_part, digest = image_name.split("@", 1)
        tag = "@" + digest
    else:
        name_part = image_name

    # Handle tag
    if ":" in name_part.split("/")[-1]:
        name_part_without_tag, tag = name_part.rsplit(":", 1)
        # Check if the part after the colon is part of a port number
        if "/" in tag:
             name_part_without_tag = name_part
             tag = "latest"
        else:
            name_part = name_part_without_tag


    # Split the remaining name part to find the registry
    parts = name_part.split("/", 1)
    repository = name_part

    if len(parts) == 2 and ("." in parts[0] or ":" in parts[0]):
        registry = parts[0]
        repository = parts[1]

    if registry == "docker.io": registry = "registry-1.docker.io"

    # Handle official Docker Hub images where "library/" is implied
    if registry == "registry-1.docker.io" and "/" not in repository:
        repository = "library/" + repository

    return {
        "registry": registry,
        "repository": repository,
        "tag": tag
    }


def assume_role(account_id, role_name):
    try:
        # Build the role ARN using the account ID and the role name
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

        # Assume the role
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CrossAccountSession"
        )

        # Extract the temporary credentials
        credentials = response["Credentials"]
        print(f"Assumed role in account {account_id} successfully")

        # Return the credentials
        return credentials
    except ClientError as e:
        print(f"Failed to assume role in account {account_id}: {e}")
        return None


def format_params(params):
    """Format query parameters from a URL, and remove any parameters with empty values"""

    # Filter out empty parameters
    filtered_params = {k: v for k, v in params.items() if v}

    # Convert query parameters dictionary to query string
    return urlencode(filtered_params)


def image_in_registry_scan(image: str, prismaAPI: PrismaAPI):
    """Search if an specified image is in the registry scanning results"""

    params = {
        "compact": True,
        "search": image
    }
    # Check if image exists in the registry scanning
    response = prismaAPI.compute_request(f"/api/v1/registry?{format_params(params)}", method="GET", skip_error=True)
    
    if response: return True
    
    return False


def generate_protected_task(
        task_definition,
        region,
        prismaAPI: PrismaAPI,
        registry_type="aws", 
        registry_credentialID="",
        filesystem_monitoring=False,
        interpreter="",
        cloud_formation=False, 
        defender_image="",
        defender_image_pullsecret=""
):
    """Generate Protected Fargate Task"""
    container_definitions = task_definition.pop("containerDefinitions")
    protected_definitions = []
    
    for container_definition in container_definitions:
        task_definition["containerDefinitions"] = [container_definition]
        image = container_definition["image"]
        image_details = {
            "docker_user": DOCKER_USER,
            "docker_pass": DOCKER_PASS,
            **parse_docker_image(image)
        }
        entrypoint = ""
        command = ""

        # Remove empty entrypoint
        if "entryPoint" in container_definition:
            if not container_definition["entryPoint"]:
                del container_definition["entryPoint"]
            else:
                entrypoint = container_definition["entryPoint"]


        # Remove empty command
        if "command" in container_definition:
            if not container_definition["command"]:
                del container_definition["command"]
            else:
                command = container_definition["command"]
        
        if not entrypoint:
            extracted_entrypoint_cmd = image_entrypoint_cmd(**image_details)
            os.environ["AWS_DEFAULT_REGION"] = region

            if extracted_entrypoint_cmd:
                if extracted_entrypoint_cmd["entryPoint"]:
                    container_definition["entryPoint"] = extracted_entrypoint_cmd["entryPoint"]
                    if not command and extracted_entrypoint_cmd["command"]:
                            container_definition["command"] = extracted_entrypoint_cmd["command"]
                            
                else:
                    if not command:
                        container_definition["entryPoint"] = extracted_entrypoint_cmd["command"]
                    else:
                        container_definition["entryPoint"] = command

        extract_entrypoint = not "entryPoint" in container_definition

        # Performing Entrypoint extraction if required
        if extract_entrypoint:
            if image_in_registry_scan(image, prismaAPI):
                registry_type = ""
                registry_credentialID = ""
            
            else:
                if not registry_credentialID and image_details["registry"].endswith(".amazonaws.com"):
                    print(f"Image {image} not found in registries. Extracting from credentials")
                    registry_credentialID = image_details["registry"].split(".")[0]
        
        else:
            registry_type = ""
            registry_credentialID = ""

        params = {
            "consoleaddr": PCC_SAN,
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
        response = prismaAPI.compute_request(f"/api/v1/defenders/fargate.json?{format_params(params)}", body=task_definition, skip_error=True)
        protected_definitions.append(response["containerDefinitions"][0])

    if len(protected_definitions) == 1:
        return response
    else:
        response["containerDefinitions"] = protected_definitions + [response["containerDefinitions"][-1]]
        return response


def get_clusters():
    """Retrieve all ECS clusters"""
    clusters = []
    paginator = ecs_client.get_paginator("list_clusters")
    for page in paginator.paginate():
        clusters.extend(page["clusterArns"])
        
    return clusters


def get_services(cluster_name):
    """Retrieve all services within a specified ECS cluster"""
    services = []
    paginator = ecs_client.get_paginator("list_services")
    for page in paginator.paginate(cluster=cluster_name):
        services.extend(page["serviceArns"])

    return services


def register_task_definition(task_definition):
    """Register a new ECS task definition"""
    waas_port_included = False
    try:
        for container_idx in range(len(task_definition["containerDefinitions"])):
            # Include WAAS port for web apps
            if WAAS_PORT and not waas_port_included:
                if "portMappings" in task_definition["containerDefinitions"][container_idx]:
                    if task_definition["containerDefinitions"][container_idx]["portMappings"]:
                        include_waas_port = True
                        for port_map in task_definition["containerDefinitions"][container_idx]["portMappings"]:
                            if port_map["containerPort"] == WAAS_PORT and port_map["protocol"] == "tcp":
                                print(f"WAAS Port {WAAS_PORT} is already configured or in use by the application")
                                include_waas_port = False

                        if include_waas_port:
                            task_definition["containerDefinitions"][container_idx]["portMappings"].append(
                                {
                                    "containerPort": WAAS_PORT,
                                    "hostPort": WAAS_PORT,
                                    "protocol": "tcp"
                                }
                            )
                            waas_port_included = True


            # Verify if the parameter "logConfiguration" inside the container definitions is empty. If is, delete it
            if "logConfiguration" in task_definition["containerDefinitions"][container_idx]:
                logConfiguration = task_definition["containerDefinitions"][container_idx]["logConfiguration"]
                if not logConfiguration:
                    del task_definition["containerDefinitions"][container_idx]["logConfiguration"]

        response = ecs_client.register_task_definition(**task_definition)
        return response["taskDefinition"]["taskDefinitionArn"]
    
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
        region,
        prismaAPI: PrismaAPI,
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

    # Check all existing services
    for service_arn in service_arns:
        service_desc = ecs_client.describe_services(cluster=cluster_name, services=[service_arn])
        if "services" in service_desc and len(service_desc["services"]) > 0:
            for service in service_desc["services"]:
                # Verify if the task definition used by the service is used by FARGATE
                is_fargate_task = False
                if "capacityProviderStrategy" in service:
                    for capacityProviderStrategy in service["capacityProviderStrategy"]:
                        if capacityProviderStrategy["capacityProvider"] == "FARGATE" and capacityProviderStrategy["weight"] > 0:
                            is_fargate_task = True
                
                elif "launchType" in service:
                    if service["launchType"] == "FARGATE":
                        is_fargate_task = True

                if is_fargate_task:
                    defended_task = False
                    task_definition_arn = service["taskDefinition"]
                    task_definition_desc = ecs_client.describe_task_definition(taskDefinition=task_definition_arn)
                    task_definition = task_definition_desc["taskDefinition"]

                    # Remove attributes that make conflict when craeting a task definition
                    for attribute in TASK_DEFINITION_REMOVED_ATTRIBUTES:
                        if attribute in task_definition:
                            del task_definition[attribute]

                    defended_task = task_definition["containerDefinitions"][-1]["name"] == "TwistlockDefender"
                    current_defender_image = task_definition["containerDefinitions"][-1]["image"]

                    if not defended_task:
                        print(f"Service {service_arn} does not have defender installed. Installing it")
                        # Protect task and update existing service
                        protected_task = generate_protected_task(
                            task_definition,
                            region,
                            prismaAPI,
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
                            task_definition["containerDefinitions"][-1]["image"] = new_defender_image
                            sample_protected_task_definition["containerDefinitions"][-1]["environment"][3]["value"] = new_ws_address
                            
                            for container in task_definition["containerDefinitions"]:
                                # Change entrypoint begining from old defender versions
                                if container["entryPoint"][0] == "/var/lib/twistlock/fargate/fargate_defender.sh":
                                   container["entryPoint"][0] = "/var/lib/twistlock/fargate/defender" 

                                # Replace environment variables
                                for envvar in container["environment"]:
                                    if envvar["name"] == "INSTALL_BUNDLE": 
                                        envvar["value"] = new_install_bundle
                                    
                                    if envvar["name"] == "WS_ADDRESS": 
                                        envvar["value"] = new_ws_address
                                
                                    elif envvar["name"] == "FILESYSTEM_MONITORING": 
                                        envvar["value"] = str(filesystem_monitoring).lower()
                                    
                                    elif envvar["name"] == "FIPS_ENABLED": 
                                        envvar["value"] = str(fips_enabled).lower()

                            # Update existing service with the changed task
                            new_task_definition_arn = register_task_definition(task_definition)
                            update_service(cluster_name, service_arn, new_task_definition_arn)


if __name__ == "__main__":
    prismaAPI = PrismaAPI(
        prisma_api_endpoint=None,
        compute_api_endpoint=PCC_URL,
        username=PCC_USER,
        password=PCC_PASS,
        debug=DEBUG
    )

    # Extract variables from current defender deployment
    with open(SAMPLE_FILE) as sample_fargate_task:
        sample_task_definition = json.loads(sample_fargate_task.read())
        sample_protected_task_definition = generate_protected_task(
            sample_task_definition, 
            os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            prismaAPI
        )
        new_defender_image = sample_protected_task_definition["containerDefinitions"][-1]["image"]
        new_install_bundle = sample_protected_task_definition["containerDefinitions"][-1]["environment"][0]["value"]
        new_ws_address = sample_protected_task_definition["containerDefinitions"][-1]["environment"][3]["value"]
        new_version = re.findall(VERSION_REGEX, new_defender_image)[0].replace("_", ".")
        print(f"Current defender version {new_version}")

    # List all or selected accounts in the organization
    accounts = ACCOUNTS
    if not ACCOUNTS[0]:
        accounts = []
        if DEPLOYMENT_MODE:
            accounts_details = org_client.list_accounts()["Accounts"]
            for account_detail in accounts_details:
                accounts.append(account_detail["Id"])
        else:
            accounts = [sts_client.get_caller_identity()["Account"]]
    
    print(f"Accounts to cover: {",".join(accounts)}")
    if WAAS_PORT:
        print(f"Configured WAAS with port: {WAAS_PORT}")

    for account in accounts:
        print(f"Attempting to assume role in account Id {account}")

        # Assume the role in the account
        credentials = assume_role(account, ROLE_NAME)

        if credentials:
            # Create a new session with the assumed role credentials:
            assumed_session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"]
            )

            # Use the EC2 client to list available regions, as ECS operates in all EC2 regions
            ec2_client = assumed_session.client("ec2")

            # Get the list of all available or selected regions
            regions = REGIONS
            if not REGIONS[0]:
                regions_details = ec2_client.describe_regions()
                regions = [region["RegionName"] for region in regions_details["Regions"]]
            
            print(f"Regions to cover: {",".join(regions)}")
                 
            for region in regions:
                try:
                    # Set the region to use as environment variable
                    os.environ["AWS_DEFAULT_REGION"] = region
                    print(f"Accessing region {region}")

                    # Initialize the Boto3 client for ECS
                    ecs_client = assumed_session.client("ecs")

                    # Get list of clusters
                    clusters = get_clusters()

                    # Loop through each cluster and get services and task definitions
                    for cluster in clusters:
                        if CLUSTERS[0]:
                            if not cluster in CLUSTERS:
                                print(f"Cluster excluded: {cluster}. Reason: Not part of the clusters' list")
                                continue

                        print(f"Accessing cluster: {cluster}")
                        services = get_services(cluster)
                        protect_fargate_task_definitions(
                            cluster, 
                            services,
                            region,
                            prismaAPI,
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