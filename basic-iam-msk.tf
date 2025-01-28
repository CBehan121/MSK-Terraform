provider "aws" {
  access_key = ""
  region = "eu-north-1"
  secret_key = ""
  skip_credentials_validation = true
  skip_metadata_api_check = true
  skip_requesting_account_id  = true
}


##Create default network reources
module "create_aws_network_resources" {
  providers = {
    aws = aws
  }
  source = "./modules/create-aws-network-resources"
}


## Create security group for the EC2 kafka admin instance
module "EC2_security_group" {
  source = "terraform-aws-modules/security-group/aws"

  name        = "access-ec"
  description = "Security group for user-service with custom ports open within VPC, and PostgreSQL publicly open"
  vpc_id      = module.create_aws_network_resources.vpc_id

  ingress_cidr_blocks      = []
  ingress_rules            = []
  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "User-service ports"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      description = "For installing requirments"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "For installing requirments"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
}

##Create the MSK security group with added rule to accept requests from EC2 kafka admin security group
module "msk_security_group" {
  depends_on = [ module.EC2_security_group ]
  source = "terraform-aws-modules/security-group/aws"

  name        = "access-MSK-from-ec"
  description = "Security group for EC2 to access MSK"
  vpc_id      = module.create_aws_network_resources.vpc_id

  ingress_cidr_blocks      = []
  ingress_rules            = []
  computed_ingress_with_source_security_group_id = [
    {
      protocol    = "tcp"
      from_port = 9098
      to_port = 9098
      source_security_group_id = module.EC2_security_group.security_group_id
    },
  ]
  number_of_computed_ingress_with_source_security_group_id = 1
}

## Add MSK cluster source security to EC2 kafka admin security group 
resource "aws_security_group_rule" "add_9098_to_send_to_MSK" {
  depends_on = [module.msk_security_group, module.EC2_security_group]
  type              = "egress"
  from_port         = 9098
  to_port           = 9098
  protocol          = "tcp"
  source_security_group_id = module.msk_security_group.security_group_id
  security_group_id = module.EC2_security_group.security_group_id
}


## Create IAM policy to manage kafka and delete EC2 instances
module "create_kafka_admin_iam_role_and_policy" {
  providers = {
    aws = aws
  }
  source = "./modules/create-iam-roles"
  iam_policy_name = "MSK-admin-policy"
  iam_role_name = "MSK-admin-role"
  iam_policy_description = "Grants kafka cluster permissions"
  iam_role_description = "Allows kafka cluster permissions to used from an EC"
  iam_role_statement = [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ] 
  iam_policy_statement = [
      {
        Action   = [
          "kafka-cluster:*",
          "ec2:TerminateInstances"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
}

##Create a profile to attach to the kafka admin EC2 instance
resource "aws_iam_instance_profile" "kafka-admin" {
    name = "kafka-admin"
    role = "MSK-admin-role"
}

## Create/Delete the kafka admin EC2 instance and make all required topics and services
module "ec2_instance" {
  depends_on = [ module.EC2_security_group, module.msk_kafka_cluster ]
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = "kafka-administration-ec2"
  ami = "ami-09423ec3aa48e9438"
  instance_type          = "t3.micro"
  monitoring             = false
  vpc_security_group_ids = [module.EC2_security_group.security_group_id]
#  subnet_id              = "subnet-eddcdzz4"
  iam_instance_profile = aws_iam_instance_profile.kafka-admin.name
    user_data = <<-EOL
  #!/bin/bash
  sudo yum -y install java-11
  cd /home/ec2-user
  wget "https://archive.apache.org/dist/kafka/3.6.1/kafka_2.13-3.6.1.tgz"
  tar xvf kafka_2.13-3.6.1.tgz
  rm kafka_2.13-3.6.1.tgz
  cd kafka_2.13-3.6.1/libs
  wget https://github.com/aws/aws-msk-iam-auth/releases/download/v1.1.1/aws-msk-iam-auth-1.1.1-all.jar
  cd ../bin
  printf "security.protocol=SASL_SSL\nsasl.mechanism=AWS_MSK_IAM\nsasl.jaas.config=software.amazon.msk.auth.iam.IAMLoginModule required;\nsasl.client.callback.handler.class=software.amazon.msk.auth.iam.IAMClientCallbackHandler" >> client.properties
  ./kafka-topics.sh --create --bootstrap-server ${(split(",", module.msk_kafka_cluster.bootstrap_brokers_sasl_iam))[0]} --command-config client.properties --replication-factor 2 --partitions 1 --topic test3
  aws ec2 terminate-instances --instance-id $(cat /var/lib/cloud/data/instance-id)
  EOL
}

## Create role to allow MSK to perform cloadwatchlogging actions
resource "aws_iam_role" "msk_iam_role" {
  name = "MSKCloudWatchLoggingRole"
  assume_role_policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Statement": {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "kafka.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  }
  POLICY
}
## Create cloudwatch log group
resource "aws_cloudwatch_log_group" "msk_log_group" {
  name = "cloudwatch_log_group"
}
## Create AWS s3 bucket for storing logs
resource "aws_s3_bucket" "msk_bucket" {
  bucket = "msk-bucket-logs"
  force_destroy = true
}


## Create the MSK cluster
module "msk_kafka_cluster" {
  source = "terraform-aws-modules/msk-kafka-cluster/aws"

  name                   = "kafka-cluster-new"
  kafka_version          = "3.6.0"
  number_of_broker_nodes = 2
#  enhanced_monitoring    = "PER_TOPIC_PER_PARTITION"

  broker_node_client_subnets = module.create_aws_network_resources.subnet_ids
  broker_node_storage_info = {
    ebs_storage_info = { volume_size = 2 }
  }
  broker_node_instance_type   = "kafka.t3.small"
  broker_node_security_groups = [module.msk_security_group.security_group_id]

  encryption_in_transit_client_broker = "TLS"
  encryption_in_transit_in_cluster    = true

#  configuration_name        = "example-configuration"
#  configuration_description = "Example configuration"
  configuration_server_properties = {
    "auto.create.topics.enable" = true
    "delete.topic.enable"       = true
  }

  jmx_exporter_enabled    = false
  node_exporter_enabled   = false
  cloudwatch_logs_enabled = true
  s3_logs_enabled         = true
  s3_logs_bucket          = "msk-bucket-logs"
  s3_logs_prefix          = "kafka-cluster"
  enable_storage_autoscaling = false
#  scaling_max_capacity = 512
#  scaling_target_value = 80

  client_authentication = {
    sasl = { iam = true }
  }
#  create_scram_secret_association = true
#  scram_secret_association_secret_arn_list = [
#    aws_secretsmanager_secret.one.arn,
#    aws_secretsmanager_secret.two.arn,
#  ]
  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}






