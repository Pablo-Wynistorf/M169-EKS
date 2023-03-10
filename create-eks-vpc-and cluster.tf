provider "aws" {
  region = "eu-central-2"
}
# Create a VPC
resource "aws_vpc" "eks-vpc" {
  cidr_block = "10.3.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags = {
    Name = "EKS-VPC"
  }
}
 
#create ssh key pair
resource "aws_key_pair" "ssh-key" {
  key_name   = "eks-nodes"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

#download key pair
resource "local_file" "ssh-key" {
    content  = tls_private_key.rsa.private_key_pem
    filename = "eks-nodes.pem"
}

# Create an Internet Gateway
resource "aws_internet_gateway" "internet-gateway" {
  vpc_id = aws_vpc.eks-vpc.id
}


# Create a route table
resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.eks-vpc.id
  route {
cidr_block = "0.0.0.0/0"
gateway_id = "${aws_internet_gateway.internet-gateway.id}"
}
}


# Create a private subnet-a
resource "aws_subnet" "eks-a-1" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.1.0/24"
  availability_zone = "eu-central-2a"
  map_public_ip_on_launch = true
    tags = {
    Name = "eks-a-1"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}
resource "aws_subnet" "eks-a-2" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.2.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2a"
    tags = {
    Name = "eks-a-2"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}
resource "aws_subnet" "eks-a-3" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.3.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2a"
    tags = {
    Name = "eks-a-3"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}

# Create a private subnet-b
resource "aws_subnet" "eks-b-1" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.4.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2b"
    tags = {
    Name = "eks-b-1"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}
resource "aws_subnet" "eks-b-2" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.5.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2b"
    tags = {
    Name = "eks-b-2"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}
resource "aws_subnet" "eks-b-3" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.6.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2b"
    tags = {
    Name = "eks-b-3"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}

# Create a private subnet-c
resource "aws_subnet" "eks-c-1" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.7.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2c"
    tags = {
    Name = "eks-c-1"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}
resource "aws_subnet" "eks-c-2" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.8.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2c"
    tags = {
    Name = "eks-c-2"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}
resource "aws_subnet" "eks-c-3" {
  vpc_id     = aws_vpc.eks-vpc.id
  cidr_block = "10.3.9.0/24"
  map_public_ip_on_launch = true
  availability_zone = "eu-central-2c"
    tags = {
    Name = "eks-c-3"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}


resource "aws_route_table_association" "Connect-eks-a-1" {
subnet_id = "${aws_subnet.eks-a-1.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}

resource "aws_route_table_association" "Connect-eks-a-2" {
subnet_id = "${aws_subnet.eks-a-2.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}

resource "aws_route_table_association" "Connect-eks-a-3" {
subnet_id = "${aws_subnet.eks-a-3.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}


resource "aws_route_table_association" "Connect-eks-b-1" {
subnet_id = "${aws_subnet.eks-b-1.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}

resource "aws_route_table_association" "Connect-eks-b-2" {
subnet_id = "${aws_subnet.eks-b-2.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}

resource "aws_route_table_association" "Connect-eks-b-3" {
subnet_id = "${aws_subnet.eks-b-3.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}




resource "aws_route_table_association" "Connect-eks-c-1" {
subnet_id = "${aws_subnet.eks-c-1.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}

resource "aws_route_table_association" "Connect-eks-c-2" {
subnet_id = "${aws_subnet.eks-c-2.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}

resource "aws_route_table_association" "Connect-eks-c-3" {
subnet_id = "${aws_subnet.eks-c-3.id}"
route_table_id = "${aws_route_table.main_route_table.id}"
}


# Create a security group
resource "aws_security_group" "SSH" {
  name        = "SSH"
  description = "SSH Port 22 Open"
  vpc_id      = aws_vpc.eks-vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}




resource "aws_security_group" "http" {
  name        = "HTTP"
  description = "HTTP Port 80 Open"
  vpc_id      = aws_vpc.eks-vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "https" {
  name        = "HTTPS"
  description = "HTTPS Port 443 Open"
  vpc_id      = aws_vpc.eks-vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_security_group" "no-ingress" {
  name        = "NO-INGRESS"
  description = "All Ports closed"
  vpc_id      = aws_vpc.eks-vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_security_group" "open-ingress" {
  name        = "OPEN-INGRESS"
  description = "All Ports open"
  vpc_id      = aws_vpc.eks-vpc.id

  ingress {
    from_port = 0
    to_port = 65535
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}





resource "aws_security_group" "loadbalancer" {
  name        = "LoadBalancer-HTTP-HTTPS"
  description = "Application Loadbalancer Port 80 and 443 open"
  vpc_id      = aws_vpc.eks-vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}



resource "aws_security_group" "http-by-loadbalancer" {
  name        = "HTTP by LoadBalancer"
  description = "Allows connections from the Securitygroup of the Loadbalancer"
  vpc_id      = aws_vpc.eks-vpc.id

  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    security_groups = ["${aws_security_group.loadbalancer.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}



resource "aws_security_group" "db-sg-db-site" {
  name        = "db-sg-db-site"
  description = "Allows traffik on tcp port 3306 by security group"
  vpc_id      = "${aws_vpc.eks-vpc.id}"
  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    security_groups = ["${aws_security_group.db-sg-ec2-site.id}"]
  }
}

resource "aws_security_group" "db-sg-ec2-site" {
  name        = "db-sg-ec2-site"
  description = "Allows traffik on tcp port 3306 by security group"
  vpc_id      = "${aws_vpc.eks-vpc.id}"
}




#Create a security group
resource "aws_security_group" "open-ingress-by-sg-ingress-site" {
  name        = "open-ingress-by-sg-ingress-site"
  description = "Allows all connections from selected security group"
  vpc_id      = "${aws_vpc.eks-vpc.id}"
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    security_groups = ["${aws_security_group.open-ingress-by-sg-connect-site.id}"]
  }  
}
#Create a security group
resource "aws_security_group" "open-ingress-by-sg-connect-site" {
  name        = "open-ingress-by-sg-connect-site"
  description = "Allows all connections from selected security group"
  vpc_id      = "${aws_vpc.eks-vpc.id}"
}





resource "aws_iam_role" "createEKSClusterRole" {
  name = "eksClusterRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "eks.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role" "createEKSNodeRole" {
  name = "eksNodeRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_AmazonEKSClusterPolicyCluster" {
  role       = aws_iam_role.createEKSClusterRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}


resource "aws_iam_role_policy_attachment" "attach_AmazonEKSClusterPolicyNode" {
  role       = aws_iam_role.createEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}



resource "aws_iam_role_policy_attachment" "attach_AmazonEKSWorkerNodePolicy" {
  role       = aws_iam_role.createEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}



resource "aws_iam_role_policy_attachment" "attach_AmazonEC2ContainerRegistryReadOnlyPolicy" {
  role       = aws_iam_role.createEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "attach_AmazonEKS_CNI_Policy" {
  role       = aws_iam_role.createEKSNodeRole.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}



data "aws_caller_identity" "current" {}




resource "aws_eks_cluster" "eks-cluster" {
  name = "EKS-Cluster"
  role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/eksClusterRole"
  vpc_config {
    subnet_ids = [aws_subnet.eks-a-1.id, aws_subnet.eks-b-1.id, aws_subnet.eks-c-1.id]
    security_group_ids = [aws_security_group.https.id]
  }
}



resource "aws_eks_node_group" "eks-cluster-node-group" {
  cluster_name = aws_eks_cluster.eks-cluster.name
  node_group_name = "eks-cluster-node-group"
  subnet_ids = [aws_subnet.eks-a-1.id, aws_subnet.eks-b-1.id, aws_subnet.eks-c-1.id]
  node_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/eksNodeRole"
  scaling_config {
    desired_size = 3
    max_size = 3
    min_size = 3
  }
  disk_size = 20
  instance_types = ["t3.medium"]
  remote_access {
    ec2_ssh_key = "eks-nodes"
  }
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.eks-cluster.name
  addon_name = "kube-proxy"
}


resource "aws_eks_addon" "amazon_vpc_cni" {
  cluster_name = aws_eks_cluster.eks-cluster.name
  addon_name = "vpc-cni"
}



resource "null_resource" "send-ps-command" {
  provisioner "local-exec" {
    command = "aws eks --region eu-central-2 update-kubeconfig --name ${aws_eks_cluster.eks-cluster.name}"
  }
}
