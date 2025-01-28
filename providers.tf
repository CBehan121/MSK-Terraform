terraform {
  required_providers {
    kafka = {
      source = "Mongey/kafka"
      version = "0.8.1"
    }
    aws = {
      source = "hashicorp/aws"
      version = "5.83.1"
    }
    random = {
      source = "hashicorp/random"
      version = "3.6.3"
    }
    jks = {
      source = "paragor/jks"
      version = "0.9.0"
    }
    tls = {
      source = "hashicorp/tls"
      version = "4.0.6"
    }  
  }
}