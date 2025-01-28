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
  name        = "EC2 security group"
  description = "This security group ensures EC2 connect works and that I can yum install/wget"
  vpc_id      = module.create_aws_network_resources.vpc_id

  ingress_cidr_blocks      = []
  ingress_rules            = []
  ingress_with_cidr_blocks = [
    {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      description = "User service ports"
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
      from_port = 9094
      to_port = 9094
      source_security_group_id = module.EC2_security_group.security_group_id
    },
  ]
  number_of_computed_ingress_with_source_security_group_id = 1
}

## Add MSK cluster source security to EC2 kafka admin security group 
resource "aws_security_group_rule" "add_9094_to_send_to_MSK" {
  depends_on = [module.msk_security_group, module.EC2_security_group]
  description = "Open egress port the MSK security group"
  type              = "egress"
  from_port         = 9094
  to_port           = 9094
  protocol          = "tcp"
  source_security_group_id = module.msk_security_group.security_group_id
  security_group_id = module.EC2_security_group.security_group_id
}


resource "aws_iam_policy" "msk_admin_policy" {
  name        = "MSK-admin-policy"
  description = "Grants kafka cluster permissions and permission to terminate EC2 instances"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = [
          "kafka-cluster:*",
          "ec2:TerminateInstances"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "msk_admin_role" {
  name        = "MSK-admin-role"
  description = "Allows kafka cluster permissions to be used from an EC2 instance"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ] 
  })
}

resource "aws_iam_role_policy_attachment" "msk_admin_policy_attachment" {
  role       = aws_iam_role.msk_admin_role.name
  policy_arn = aws_iam_policy.msk_admin_policy.arn
}


##Create a profile to attach to the kafka admin EC2 instance
resource "aws_iam_instance_profile" "kafka_admin" {
    name = "kafka-admin"
    role = "MSK-admin-role"
}

##Create an EC2 instance that will start run some commands against kafka and then terminate itself
module "ec2_instance_2" {
  depends_on = [ module.EC2_security_group, module.msk_kafka_cluster, jks_key_store.msk_admin_keystore ]
  source  = "terraform-aws-modules/ec2-instance/aws"
  name = "kafka-administration-ec2"
  ami = "ami-09423ec3aa48e9438"
  instance_type          = "t3.micro"
  monitoring             = false
  vpc_security_group_ids = [module.EC2_security_group.security_group_id]
  iam_instance_profile = aws_iam_instance_profile.kafka_admin.name
    user_data = <<-EOL
  #!/bin/bash
  sudo yum -y install java-11
  cd /home/ec2-user
  wget "https://archive.apache.org/dist/kafka/3.6.1/kafka_2.13-3.6.1.tgz"
  tar xvf kafka_2.13-3.6.1.tgz
  rm kafka_2.13-3.6.1.tgz
  echo ${ (split(",", module.msk_kafka_cluster.bootstrap_brokers_tls))[0] } > bootstrap.txt
  echo ${jks_key_store.msk_admin_keystore.jks } > keystore.jks
  base64 -d keystore.jks > decoded-keystore.jks
  cp /usr/lib/jvm/jra-11/lib/security/cacerts kafka.client.truststore.jks
  printf "security.protocol=SSL\nssl.truststore.location=/home/ec2-user/kafka.client.truststore.jks\nssl.keystore.location=/home/ec2-user/keystore.jks\nssl.keystore.password=123456\nssl.key.password=123456 >> client.properties"
  aws ec2 terminate-instances --instance-id $(cat /var/lib/cloud/data/instance-id)
  EOL
} 

## Create role to allow MSK to perform cloadwatchlogging actions
resource "aws_iam_role" "msk_cloudwatch_role" {
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
## Create AWS s3 bucket for storing logs, force destroy was added here along with 
## specifying the aws = aws provider in some cases because S3buckets were being made in regions i had no control to delete
resource "aws_s3_bucket" "msk_bucket" {
  bucket = "msk-bucket-logs"
  force_destroy = true
}
##Associates the msk_root_certificate with the msk_root_certificate_authority
resource "aws_acmpca_certificate_authority_certificate" "msk_certificate_auth_certificate" {
  certificate_authority_arn = aws_acmpca_certificate_authority.msk_root_certificate_authority.arn

  certificate       = aws_acmpca_certificate.msk_root_certificate.certificate
  certificate_chain = aws_acmpca_certificate.msk_root_certificate.certificate_chain
}

#Create the resource to issue certificates
resource "aws_acmpca_certificate" "msk_root_certificate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.msk_root_certificate_authority.arn
  certificate_signing_request = aws_acmpca_certificate_authority.msk_root_certificate_authority.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 2
  }
}

data "aws_partition" "current" {}

## Create the ROOT certificate authority
resource "aws_acmpca_certificate_authority" "msk_root_certificate_authority" {
  type = "ROOT"
  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "temp-common-name"
    }
  }
}



## Create the MSK admin private key
resource "tls_private_key" "msk_admin_private_key" {
  algorithm = "RSA"
}
## Create the MSK admin certificate request, only set with the dns name im testing against
resource "tls_cert_request" "msk_admin_cert_request" {
  private_key_pem = tls_private_key.msk_admin_private_key.private_key_pem
    subject {
    common_name  = "temp-name"
  }
  dns_names = [ substr((split(",", module.msk_kafka_cluster.bootstrap_brokers_tls))[0] , 0, length((split(",", module.msk_kafka_cluster.bootstrap_brokers_tls))[0]) -5) ]
}
##Create the MSK admin certificate
resource "aws_acmpca_certificate" "msk_admin_certificate" {
  certificate_signing_request = tls_cert_request.msk_admin_cert_request.cert_request_pem
  certificate_authority_arn = aws_acmpca_certificate_authority.msk_root_certificate_authority.arn
  signing_algorithm = "SHA512WITHRSA"
  validity {
    type  = "DAYS"
    value = 365
  }
}
## Create the MSK admin keystore 
resource "jks_key_store" "msk_admin_keystore" {
  depends_on = [ aws_acmpca_certificate.msk_admin_certificate]
  certificate_chain = [
    aws_acmpca_certificate.msk_admin_certificate.certificate
  ]
  ca          = aws_acmpca_certificate.msk_root_certificate.certificate
  private_key = tls_private_key.msk_admin_private_key.private_key_pem
  password    = "123456"
}



## A very basic and cheap MSK cluster. Needs to be zookeeper instead of kraft to save on costs
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
    tls = { certificate_authority_arns = [aws_acmpca_certificate_authority.msk_root_certificate_authority.arn]}
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

