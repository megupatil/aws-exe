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

# ------------------------------------------------------------------------------
# NETWORKING (Multi-AZ)
# ------------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr
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
    Name = "${var.project_name}-public-subnet-az1"
  }
}

resource "aws_subnet" "private_az1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_az1_cidr
  availability_zone = "${var.aws_region}a"
  tags = {
    Name                              = "${var.project_name}-private-subnet-az1"
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
    Name = "${var.project_name}-public-subnet-az2"
  }
}

resource "aws_subnet" "private_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_az2_cidr
  availability_zone = "${var.aws_region}b"
  tags = {
    Name                              = "${var.project_name}-private-subnet-az2"
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

  ingress {
    description     = "MongoDB from EKS Nodes"
    from_port       = 27017
    to_port         = 27017
    protocol        = "tcp"
    security_groups = [aws_eks_cluster.main.vpc_config[0].cluster_security_group_id]
  }

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

resource "aws_s3_bucket_policy" "db_backups_policy" {
  depends_on = [aws_s3_bucket_public_access_block.db_backups_pab]
  bucket     = aws_s3_bucket.db_backups.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = "*",
      Action    = ["s3:ListBucket"], # Allows public listing
      Resource  = [aws_s3_bucket.db_backups.arn]
    }]
  })
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
  user_data = templatefile("${path.module}/mongodb-setup.sh", {
    db_user     = "wizadmin"
    db_password = "verysecretpassword123"
  })
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

  # FIX: Add an explicit dependency on the S3 bucket policy.
  # This forces Terraform to fully create the S3 bucket and its configuration
  # before starting the lengthy EKS cluster creation process.
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_s3_bucket_policy.db_backups_policy,
  ]
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
  name = "${var.project_name}/app"
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

output "ecr_repository_url" {
  description = "URL of the ECR repository."
  value       = aws_ecr_repository.app.repository_url
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster."
  value       = aws_eks_cluster.main.name
}
