# Prisma Cloud Fargate Defender Deployment 
​​This repo showcases the process of how to deploy Fargate Defenders on ECS Services at Org Level by creating a Fargate task the does it.

## Introduction
### Objective
<br>
Deploy Fargate Defender across all or specified ECS Services in an AWS Org or a Single Account.

### Environment
* AWS Account
* Prisma Cloud SaaS or self-hosted tenant

### Requirements
This procedure does the next:
- Creates Service Accounts, Roles and Permissions Groups in Prisma Cloud
- Creates a secret in AWS Secrets Manager
- Deploys a CloudFormation Template
- Pushes a container image into ECR repository
- Deploys ECS Fargate Tasks and Schedule Tasks
- Reads the VPC configuration and update it if needed

Please verify that you have the appropriate access to follow up this procedure.

## Setup
### Step 1: Create Prisma Cloud Service Account
On Prisma Cloud create a permissions group with the following permissions:
- Compute > Monitor:
    - Images/Containers Vulnerabilities & Compliance Results: View

- Compute > Manage:
    - Defenders Management: View and Update

Once done, create a role as the following:
- Name: Any of your preference
- Permissions Group: The one created before
- Account Groups: All (recommended)
- Resource List: None
- Advanced Options:
    - On-prem/ Other cloud providers: Checked (recommended)

After creating the role, create the corresponding Service Account and its Access Key and Secret Key.

### Step 2: Create Secret
On AWS Secrets Manager, create a secret with the name of **PCCAccessSecret** on the region where the updater task will be executed. This secret should contain the following keys:

- **PCC_URL**: Path to the Compute Console. This should be obtained in Prisma Cloud > Runtime Security > Manage > System > Utilities > Path to the Console.
- **PCC_USER**: Access Key of the Service Account created on Step 1.
- **PCC_PASS**: Secret Key of the Service Account created on Step 1.

### Step 3: Deploy CloudFormation Template
The CFT to deploy is the one located in the file **fargateDeployCFT.yaml** of this repository. This CFT will deploy the following resources:
| Resource | Description | Creation Condition |
|-|-|-|
| MasterRole | Role to be used by the fargate updater task | - |
| MemberRole | Role to be assumed by the master role | - |
| FargateUpdaterMasterPolicy | Policy with the permissions needed to retrieve the organization details, download the updater image from ECR, and assume the Member Role | - | 
| FargateUpdaterMemberPolicy | Policy with the permissions required to be used to update existing ECS Fargate Services | - |
| FargateUpdaterLogGroup | Log group to retain the logs of the fargate updater task. The retention it's set to 7 days with at most 3 MB of required storage | FargateDeploy paramater must be "true" |
| MemberRolesStackSet | StackSet to create the resources FargateUpdaterMemberPolicy and MemberRole on each account in the Organization or a specified organization unit | DeploymentMode paramater must be "Organization" and OrganizationalUnitIds parameter must not be blank |

Also the parameters of such template are:
| Parameter | Description | Default | Required |
|-|-|-|-|
| MasterRoleName | Name of the MasterRole resource to be created | FargateDeployMaster | Yes |
| MemberRoleName | Name of the MemberRole resource to be created | FargateDeployMember | Yes |
| PrismaCloudSecret | ARN of the Secret created in Step 2 | - | Yes |
| FargateDeploy | Execute the updater inside a Fargate task. It can also be executed in a CI/CD pipeline, but it is required to update the Trust Relationship policy of the MasterRoleName according to your CI/CD provider | true | Yes |
| LogGroupName | Name of the resource FargateUpdaterLogGroup | /ecs/fargate-updater | If FargateDeploy is "true" |
| DeploymentMode | Mode of deploying the CFT. If set to "Organization", it will create member roles across the Org | Organization | Yes |
| OrganizationalUnitIds | Ids of the Organizational Units where member roles will be created | - | If DeploymentMode is "Organization" |

Upload the CFT as a CloudFormation Stack and apply the corresponding parameters. If all is successfull, then it must output the **MasterRole ARN** to be used in the task definition.


> **NOTE**: The CFT **must** be deployed in the **same account** and **region** where the updater task will be executed and the secret was created.

### Step 5: Build and Push the Image
To Build the image that will be executed as part of the Fargate Task you need the following files of this repo:
- **Dockerfile**: Image file definition.
- **fargateTask.json**: Sample fargate task to extect the Fargate defender variables.
- **requirements.txt**: dependencies file.
- **protectFargateTasks.py**: Source code to execute the tasks protection.

Once you have those files in place execute the following command:
```bash
docker build -t fargate-updater:latest .
```

Once done, its needed to push the image. It's recommeded to push the image into an ECR private repository. To do that, do the following:

1. [Create](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-create.html) the ECR repository.
2. [Authenticate](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html) to ECR.
3. Tag the image built:
```bash
docker tag fargate-updater:latest ${ECR_REPO}:latest
```
4. And finally push the image:
```bash
docker push ${ECR_REPO}:latest
```

You can also automate this process if you've already have a pipeline in place. For your reference check at he file **.github/workflows/docker-image.yml**

## Deploy
### Environment Variables
The updater has the following environment variables:
| Variable | Description | Default | Mandatory |
|-|-|-|-|
| PCC_SECRET | Name of the secret created on step 2 of the Setup | - | If not set PCC_URL, PCC_USER and PCC_PASS |
| PCC_URL | Url of the Compute console | - | If PCC_SECRET is not set |
| PCC_USER | Access Key of the Service Account | - | If PCC_SECRET is not set |
| PCC_PASS | Secret Key of the Service Account | - | If PCC_SECRET is not set |
| PCC_SAN | FQDN of the Compute Console | PCC_URL FQDN | No |
| FS_MONITOR | Enables filesystem monitoring | false | No |
| FIPS_ENABLED | Enables FIPS mode | false | No |
| REGISTRY_TYPE | Type of registry where the Fargate Tasks images are located | aws | No |
| CREDENTIAL_ID | Id of the credentials used to extract the entrypoint | - | No |
| ROLE_NAME | Name of the member role to assume | FargateDeployMember | No |
| REGIONS | Regions where to deploy the Fargate Defenders. For multiple regions separate it by comma (ex. "us-east-1,us-east-2") | - | No |
| ACCOUNTS | Accounts Ids where to deploy the Fargate Defenders. For multiple accounts separate it by comma (ex. "1111111111,1111111112") | - | No |
| CLUSTERS | Clusters ARNs where to deploy the Fargate Defenders. For multiple clusters separate it by comma | - | No |
| UPGRADE | Upgrade existing defender to latest version | true | No |
| DEPLOYMENT_MODE | Deploy defenders across the org or in a single account | ORG | No |
| WAAS_PORT | Port to configure WAAS | - | No |

This variables can be set in the task definition used.

### Fargate Task
The simplest way to deploy the updater is by using the file **fargateTaskTemplate.json** as template for your task definition. Here you must set the following values:
- **IMAGE_NAME**: Name of the image pushed to ECR repository.
- **PCC_SECRET**: Name of the secret created.
- **AWS_REGION**: Region where the Log Group was configured.
- **TASK_EXECUTION_ROLE**: ARN of the Master Role created.

You can also place any environment variable mentioned before. 

It's also recommended to execute the manual [Fargate Defender Installation](https://docs.prismacloud.io/en/enterprise-edition/content-collections/runtime-security/install/deploy-defender/app-embedded/install-app-embedded-defender-fargate) on this particular task, to extract continously vulnerabilities and compliance.

Once the task has been registered, you can create a [Standalone](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/standalone-tasks.html) task to perform the installation and upgrade only once, or execute a [Scheduled Task](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/tasks-scheduled-eventbridge-scheduler.html) to continously monitor, install and upgrade fargate defenders.