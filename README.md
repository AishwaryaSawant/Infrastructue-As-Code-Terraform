# infrastructure

Infrastructure as Code with Terraform

main.tf file will create the resources such as VPCs ,Subnet, Route Table,Internet Gateways

Variables will be passed from command line while executing the main.tf file

Commands for terraform to create the resources are

terraform init

terraform plan

terraform apply

To delete the infrastructure the delete command would be run from cli passing the variables

## Command to import SSL certificate

aws acm import-certificate --certificate fileb://prods_aishwaryas_me.crt --private-key fileb://private.key --certificate-chain fileb://prods_aishwaryas_me.ca-bundle