# tf-aws-infra
Terraform for infrastructure setup and teardown.

To run this Terraform project for infrastructure setup and teardown, you can follow these general steps:

Install Terraform: Ensure that you have Terraform installed on your local machine. You can download it from the official Terraform website.

Clone the Repository:

```bash
git clone https://github.com/JahnaviPatelOrg/tf-aws-infra.git
cd tf-aws-infra
```

Use the correct profile

```bash
export AWS_PROFILE=your-profile
```


Initialize the Terraform Working Directory:

```bash
terraform init
```

format the code

```bash
terraform fmt
```

Validate the Configuration:

```bash
terraform validate
```
Plan the Changes:

```bash
terraform plan -var-file=dev.tfvars
terraform plan -var-file=demo.tfvars
```
Apply the Changes:

```bash
terraform apply -var-file=dev.tfvars
terraform apply -var-file=demo.tfvars
```

Destroy the Infrastructure:

```bash
terraform destroy -var-file=dev.tfvars
terraform destroy -var-file=demo.tfvars
```

You may need to provide AWS credentials and other necessary variables to Terraform, either through environment variables or a terraform.tfvars file.

If there are specific instructions or additional configuration needed, you may want to check other documentation or scripts within the repository.

