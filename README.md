# MSK Terraform

There are 2 main files, this shouldn't be ran with both choose one and move the other out of the main directory.

 - basic-tls-msk.tf
	 - Sets up MSK to work with TLS based auth
	 - Creates a root and kafka-admin cert (no acls are initially set)
	 - Deploys an EC2 instance that can run some startup tasks IE create topics/ACLs
	 - Security groups are setup to allow a connection from the EC2 instance to kafka but with little else.
 - basic-iam-msk.tf
	 - Sets up MSK to work with IAM based auth
	 - The MSK_admin_role has full IAM access to the cluster 
	 - Deploys an EC2 instance that can run some startup tasks IE create topics/ACLs
	 - Security groups are setup to allow a connection from the EC2 instance to kafka but with little else.
