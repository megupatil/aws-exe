# ------------------------------------------------------------------------------
# DATA SOURCES
# ------------------------------------------------------------------------------

# Dynamically find the latest Ubuntu 20.04 AMI instead of hardcoding it.
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical's AWS account ID
}

# Get the OIDC provider URL for the EKS cluster to use with IAM Roles for Service Accounts (IRSA)
data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

# Use the http data source to download the policy from a URL
data "http" "iam_policy" {
  url = "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.5.4/docs/install/iam_policy.json"
}

data "aws_caller_identity" "current" {}

# ------------------------------------------------------------------------------
# NETWORKING (Multi-AZ)
# ------------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Enable DNS support and hostnames for the VPC, required for VPC endpoints
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Subnets in Availability Zone A
resource "aws_subnet" "public_az1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_az1_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  tags = {
    Name                                = "${var.project_name}-public-subnet-az1"
    "kubernetes.io/cluster/${var.project_name}-cluster" = "shared"
    "kubernetes.io/role/elb"            = "1"
  }
}

resource "aws_subnet" "private_az1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_az1_cidr
  availability_zone = "${var.aws_region}a"
  tags = {
    Name                              = "${var.project_name}-private-subnet-az1"
    "kubernetes.io/cluster/${var.project_name}-cluster" = "shared"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

# Subnets in Availability Zone B
resource "aws_subnet" "public_az2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_az2_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}b"
  tags = {
    Name                                = "${var.project_name}-public-subnet-az2"
    "kubernetes.io/cluster/${var.project_name}-cluster" = "shared"
    "kubernetes.io/role/elb"            = "1"
  }
}

resource "aws_subnet" "private_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_az2_cidr
  availability_zone = "${var.aws_region}b"
  tags = {
    Name                              = "${var.project_name}-private-subnet-az2"
    "kubernetes.io/cluster/${var.project_name}-cluster" = "shared"
    "kubernetes.io/role/internal-elb" = "1"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Route table for PUBLIC subnets
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public_az1" {
  subnet_id      = aws_subnet.public_az1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_az2" {
  subnet_id      = aws_subnet.public_az2.id
  route_table_id = aws_route_table.public.id
}

# NAT Gateway for EKS nodes to access the internet
resource "aws_eip" "nat" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.gw]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_az1.id # Place NAT in a public subnet
  tags = {
    Name = "${var.project_name}-nat-gw"
  }
}

# Route table for PRIVATE subnets
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = {
    Name = "${var.project_name}-private-rt"
  }
}

resource "aws_route_table_association" "private_az1" {
  subnet_id      = aws_subnet.private_az1.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_az2" {
  subnet_id      = aws_subnet.private_az2.id
  route_table_id = aws_route_table.private.id
}

# ------------------------------------------------------------------------------
# NETWORK ACL (FIX for ImagePullBackOff)
# ------------------------------------------------------------------------------
resource "aws_network_acl" "main" {
  vpc_id = aws_vpc.main.id

  egress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  ingress {
    protocol   = "-1"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  subnet_ids = [
    aws_subnet.public_az1.id,
    aws_subnet.private_az1.id,
    aws_subnet.public_az2.id,
    aws_subnet.private_az2.id,
  ]

  tags = {
    Name = "${var.project_name}-nacl"
  }
}

# ------------------------------------------------------------------------------
# VPC ENDPOINTS (FIX for ImagePullBackOff)
# ------------------------------------------------------------------------------

resource "aws_security_group" "vpc_endpoint_sg" {
  name   = "${var.project_name}-vpc-endpoint-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "Allow EKS nodes to access endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_eks_cluster.main.vpc_config[0].cluster_security_group_id]
  }

  tags = {
    Name = "${var.project_name}-vpc-endpoint-sg"
  }
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  private_dns_enabled = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = "*",
        Action    = "*",
        Resource  = "*"
      }
    ]
  })
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  private_dns_enabled = true

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = "*",
        Action    = "*",
        Resource  = "*"
      }
    ]
  })
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# Add a VPC endpoint for STS (Security Token Service)
resource "aws_vpc_endpoint" "sts" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.sts"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
  security_group_ids  = [aws_security_group.vpc_endpoint_sg.id]
  private_dns_enabled = true
}

# ------------------------------------------------------------------------------
# SECURITY GROUPS
# ------------------------------------------------------------------------------

resource "aws_security_group" "mongodb_sg" {
  name        = "${var.project_name}-mongodb-sg"
  description = "Allow SSH and MongoDB traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # WEAKNESS
  }

  # ----------------- THIS IS THE HIGHLIGHTED CHANGE -----------------
  # FIX: Allow traffic from the EKS cluster's security group directly.
  # This is the most robust way to ensure connectivity.
  ingress {
    description     = "MongoDB from EKS Nodes"
    from_port       = 27017
    to_port         = 27017
    protocol        = "tcp"
    cidr_blocks = [var.private_subnet_az1_cidr, var.private_subnet_az2_cidr]
  #  security_groups = [aws_eks_cluster.main.vpc_config[0].cluster_security_group_id]
  }
  # ------------------------------------------------------------------

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-mongodb-sg"
  }
}

resource "aws_security_group_rule" "alb_to_nodes" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  security_group_id        = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
  # Allow traffic from anywhere within the VPC
  cidr_blocks              = [var.vpc_cidr]
}


# ------------------------------------------------------------------------------
# IAM ROLES & POLICIES
# ------------------------------------------------------------------------------

resource "aws_iam_role" "mongodb_vm_role" {
  name = "${var.project_name}-mongodb-vm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "mongodb_vm_policy" {
  role       = aws_iam_role.mongodb_vm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess" # WEAKNESS
}

resource "aws_iam_instance_profile" "mongodb_vm_profile" {
  name = "${var.project_name}-mongodb-vm-profile"
  role = aws_iam_role.mongodb_vm_role.name
}

# ------------------------------------------------------------------------------
# S3 BUCKET FOR BACKUPS
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "db_backups" {
  bucket = "${var.project_name}-db-backups-${random_id.bucket_suffix.hex}"
}

resource "random_id" "bucket_suffix" {
  byte_length = 8
}

resource "aws_s3_bucket_public_access_block" "db_backups_pab" {
  bucket = aws_s3_bucket.db_backups.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_ownership_controls" "db_backups_ownership" {
  bucket = aws_s3_bucket.db_backups.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "db_backups_acl" {
  depends_on = [
    aws_s3_bucket_public_access_block.db_backups_pab,
    aws_s3_bucket_ownership_controls.db_backups_ownership
  ]
  bucket = aws_s3_bucket.db_backups.id
  acl    = "public-read" # WEAKNESS
}

data "aws_iam_policy_document" "db_backups_bucket_policy" {
  statement {
    sid       = "PublicList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.db_backups.arn]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "db_backups_policy" {
  depends_on = [aws_s3_bucket_public_access_block.db_backups_pab]
  bucket     = aws_s3_bucket.db_backups.id
  policy     = data.aws_iam_policy_document.db_backups_bucket_policy.json
}

# ------------------------------------------------------------------------------
# MONGODB EC2 INSTANCE
# ------------------------------------------------------------------------------

resource "aws_instance" "mongodb_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.db_instance_type
  subnet_id              = aws_subnet.public_az1.id
  vpc_security_group_ids = [aws_security_group.mongodb_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.mongodb_vm_profile.name
  user_data = templatefile("${path.module}/mongodb-setup.sh", {})
  key_name = aws_key_pair.deployer.key_name

  tags = {
    Name = "${var.project_name}-mongodb-server"
  }
}

resource "aws_key_pair" "deployer" {
  key_name   = "${var.project_name}-deployer-key"
  public_key = file(pathexpand("~/.ssh/id_rsa.pub"))
}

# ------------------------------------------------------------------------------
# EKS CLUSTER (KUBERNETES)
# ------------------------------------------------------------------------------

resource "aws_iam_role" "eks_cluster_role" {
  name = "${var.project_name}-eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

resource "aws_iam_role" "eks_node_role" {
  name = "${var.project_name}-eks-node-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_iam_role_policy_attachment" "ec2_container_registry_read_only" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_node_role.name
}

resource "aws_eks_cluster" "main" {
  name     = "${var.project_name}-cluster"
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids              = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]
    endpoint_private_access = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_s3_bucket_policy.db_backups_policy,
  ]
}

resource "random_pet" "node_group_version" {
  length = 2
}

resource "aws_eks_node_group" "main" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.project_name}-node-group"
  node_role_arn   = aws_iam_role.eks_node_role.arn
  subnet_ids      = [aws_subnet.private_az1.id, aws_subnet.private_az2.id]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }

  instance_types = ["t3.medium"]

  # Add a changing tag to force replacement of the node group.
  # This ensures the nodes get the latest networking configuration.
  tags = {
    "Name" = "${var.project_name}-node-group-${random_pet.node_group_version.id}"
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node_policy,
    aws_iam_role_policy_attachment.eks_cni_policy,
    aws_iam_role_policy_attachment.ec2_container_registry_read_only,
    aws_route_table_association.private_az1,
    aws_route_table_association.private_az2,
  ]
}

# ------------------------------------------------------------------------------
# ECR (Elastic Container Registry)
# ------------------------------------------------------------------------------

resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}/app"
  force_delete         = true
}

# ------------------------------------------------------------------------------
# AWS LOAD BALANCER CONTROLLER (FIX for Ingress)
# ------------------------------------------------------------------------------

# Create an OIDC provider for the EKS cluster
resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

# IAM policy for the AWS Load Balancer Controller
resource "aws_iam_policy" "alb_controller_policy" {
  name        = "${var.project_name}-alb-controller-policy"
  description = "IAM policy for the AWS Load Balancer Controller"
  policy      = data.http.iam_policy.response_body
}

# IAM role for the AWS Load Balancer Controller Service Account
resource "aws_iam_role" "alb_controller_role" {
  name = "${var.project_name}-alb-controller-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks.arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:kube-system:aws-load-balancer-controller"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "alb_controller_attach" {
  policy_arn = aws_iam_policy.alb_controller_policy.arn
  role       = aws_iam_role.alb_controller_role.name
}

# Install the AWS Load Balancer Controller using the Helm provider
resource "helm_release" "aws_load_balancer_controller" {
  name       = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  namespace  = "kube-system"
  version    = "1.5.5"

  set {
    name  = "clusterName"
    value = aws_eks_cluster.main.id
  }

  set {
    name  = "serviceAccount.create"
    value = "true"
  }

  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.alb_controller_role.arn
  }

  # FIX: Add the VPC ID to the controller's configuration
  set {
    name  = "vpcId"
    value = aws_vpc.main.id
  }
}

# ------------------------------------------------------------------------------
# OUTPUTS
# ------------------------------------------------------------------------------

output "mongodb_public_ip" {
  description = "Public IP address of the MongoDB server."
  value       = aws_instance.mongodb_server.public_ip
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket for backups."
  value       = aws_s3_bucket.db_backups.bucket
}

output "cloudtrail_log_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail audit logs."
  value       = aws_s3_bucket.cloudtrail_logs.bucket
}

output "ecr_repository_url" {
  description = "URL of the ECR repository."
  value       = aws_ecr_repository.app.repository_url
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster."
  value       = aws_eks_cluster.main.name
}

output "mongodb_private_ip" {
  description = "Private IP address of the MongoDB server (use this in app connection strings)."
  value       = aws_instance.mongodb_server.private_ip
}
# ------------------------------------------------------------------------------
# CLOUD NATIVE SECURITY - AUDIT LOGGING
# ------------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${var.project_name}-cloudtrail-logs-${random_id.bucket_suffix.hex}"
}

data "aws_iam_policy_document" "cloudtrail_s3_policy" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_s3_policy.json
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.project_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
  depends_on = [aws_s3_bucket_policy.cloudtrail_policy]
}

# ------------------------------------------------------------------------------
# CLOUD NATIVE SECURITY - DETECTIVE CONTROL
# ------------------------------------------------------------------------------

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config_role.arn
}

resource "aws_s3_bucket" "config_logs" {
  bucket = "${var.project_name}-config-logs-${random_id.bucket_suffix.hex}"
}

data "aws_iam_policy_document" "config_bucket_policy" {
  statement {
    sid       = "AWSConfigWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
  statement {
    sid       = "AWSConfigAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_logs.arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_logs_policy" {
  bucket = aws_s3_bucket.config_logs.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config_logs.bucket
  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config_logs_policy,
  ]
}

resource "aws_iam_role" "config_role" {
  name = "${var.project_name}-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "config.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_config_rule" "s3_public_read" {
  name = "s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# ------------------------------------------------------------------------------
# CLOUD NATIVE SECURITY - PREVENTATIVE CONTROL
# ------------------------------------------------------------------------------

resource "aws_wafv2_web_acl" "main" {
  name        = "${var.project_name}-waf-acl"
  scope       = "REGIONAL"
  default_action {
    allow {}
  }

  rule {
    name     = "AWS-AWSManagedRulesSQLiRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "SQLiRule"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "WAFACL"
    sampled_requests_enabled   = false
  }
}

# Get the ARN of the Application Load Balancer created by the Ingress
data "aws_lb" "app_lb" {
  depends_on = [helm_release.aws_load_balancer_controller]
  tags = {
    "elbv2.k8s.aws/cluster" = "${var.project_name}-cluster"
  }
}

resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = data.aws_lb.app_lb.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}
