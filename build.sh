#!/bin/bash

terraform init

terraform plan -var="region=us-east-1" \
               -var="cidr_block=10.0.0.0/16" \
               -var="subnet1_cidr_block=10.0.0.0/18" \
               -var="subnet2_cidr_block=10.0.64.0/18" \
               -var="subnet3_cidr_block=10.0.128.0/17" \
               -var="vpcNametag=a4_vpc" \
               -var="vpctag=MyNewVpc" \
               -var="subnet1tag=subnet1" \
               -var="subnet2tag=subnet2" \
               -var="subnet3tag=subnet3" \
               -var="gwtag=gw" \
               -var="rttag=route_table" \
               -var="sub1availzone=us-east-1a" \
               -var="sub2availzone=us-east-1b" \
               -var="sub3availzone=us-east-1c" \
               -var="ami_id=ami-06387cd012c58c527" \
               -var="username=csye6225fall2020" \
               -var="password=Ash02049494" \
               -var="cicduser=ghactions" \
               -var="app_sec_group=application" \
               -var="db_sec_group=database" \
               -var="webapp_bucket=webapp.aishwarya.sawant" \
               -var="dbsubnet_name=db-subnet-group" \
               -var="db_identifier=csye6225-f20" \
               -var="db_name=csye6225" \
               -var="dynamodb_name=csye6225" \
               -var="webappS3_policy=WebAppS3" \
               -var="EC2-CSYE6225_role=EC2-CSYE6225" \
               -var="codedeploy_bucket=codedeploy.prod.aishwaryas.me" \
               -var="CodeDeploy-EC2-S3_policy1=CodeDeploy-EC2-S3" \
               -var="CodeDeployEC2ServiceRole_role1=CodeDeployEC2ServiceRole" \
               -var="GH-Upload-To-S3_policy2=GH-Upload-To-S3" \
               -var="CodeDeployServiceRole_role2=CodeDeployServiceRole" \
               -var="GH-Code-Deploy_policy3=GH-Code-Deploy" \
               -var="AWS_account_num=663668038035" \
               -var="codedeploy_app_name=csye6225-webapp" \
               -var="codedeploy_group_name=csye6225-webapp-deployment" \
               -var="iam_ec2_profile_name=iam_ec2_profile_1" \
               -var="GH-ec2-policy=arn:aws:iam::663668038035:policy/GH-ec2-ami" \
               -var="prod_zone_id=Z07197682NF02XT9FYF9Z" \
               -var="prod_record_name=api.prod.aishwaryas.me" \
               -var="cloudwatchagent_server_policy=arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
               # -var="cloudwatchagent_admin_policy=arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy" \
            #    -var="dev_zone_id=Z07188103KMGTNYZXR1IR" \
            #    -var="dev_record_name=api.dev.aishwaryas.me"

terraform apply -auto-approve \
                -var="region=us-east-1" \
                -var="cidr_block=10.0.0.0/16" \
                -var="subnet1_cidr_block=10.0.0.0/18" \
                -var="subnet2_cidr_block=10.0.64.0/18" \
                -var="subnet3_cidr_block=10.0.128.0/17" \
                -var="vpcNametag=a4_vpc" \
                -var="vpctag=MyNewVpc" \
                -var="subnet1tag=subnet1" \
                -var="subnet2tag=subnet2" \
                -var="subnet3tag=subnet3" \
                -var="gwtag=gw" \
                -var="rttag=route_table" \
                -var="sub1availzone=us-east-1a" \
                -var="sub2availzone=us-east-1b" \
                -var="sub3availzone=us-east-1c" \
                -var="ami_id=ami-06387cd012c58c527" \
                -var="username=csye6225fall2020" \
                -var="password=Ash02049494" \
                -var="cicduser=ghactions" \
                -var="app_sec_group=application" \
                -var="db_sec_group=database" \
                -var="webapp_bucket=webapp.aishwarya.sawant" \
                -var="dbsubnet_name=db-subnet-group" \
                -var="db_identifier=csye6225-f20" \
                -var="db_name=csye6225" \
                -var="dynamodb_name=csye6225" \
                -var="webappS3_policy=WebAppS3" \
                -var="EC2-CSYE6225_role=EC2-CSYE6225" \
                -var="codedeploy_bucket=codedeploy.prods.aishwaryas.me" \
                -var="CodeDeploy-EC2-S3_policy1=CodeDeploy-EC2-S3" \
                -var="CodeDeployEC2ServiceRole_role1=CodeDeployEC2ServiceRole" \
                -var="GH-Upload-To-S3_policy2=GH-Upload-To-S3" \
                -var="CodeDeployServiceRole_role2=CodeDeployServiceRole" \
                -var="GH-Code-Deploy_policy3=GH-Code-Deploy" \
                -var="AWS_account_num=663668038035" \
                -var="codedeploy_app_name=csye6225-webapp" \
                -var="codedeploy_group_name=csye6225-webapp-deployment" \
                -var="iam_ec2_profile_name=iam_ec2_profile_1" \
                -var="GH-ec2-policy=arn:aws:iam::663668038035:policy/GH-ec2-ami" \
                -var="prod_zone_id=Z07197682NF02XT9FYF9Z" \
                -var="prod_record_name=api.prods.aishwaryas.me" \
                -var="cloudwatchagent_server_policy=arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
               #  -var="cloudwatchagent_admin_policy=arn:aws:iam::aws:policy/CloudWatchAgentAdminPolicy" \
                # -var="dev_zone_id=Z07188103KMGTNYZXR1IR" \
                # -var="dev_record_name=api.dev.aishwaryas.me"
