# =============================================================================
# Vulnerable AWS Cloud Lab — Intentional misconfigurations for security training
# WARNING: Never deploy in production. Destroy immediately after use.
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" { state = "available" }

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "${var.name_prefix}-${local.suffix}"

  # Hardcoded credentials stored in Lambda env vars — intentional finding
  db_url       = "mysql://admin:${var.db_password}@db.internal:3306/app"
  api_key      = "sk-prod-9x8y7z6w5v4u3t2s1r0q-${local.suffix}"
  secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJvd25lciJ9"
}

# ─── Networking ───────────────────────────────────────────────────────────────

resource "aws_vpc" "lab" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${local.name}-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags = { Name = "${local.name}-public" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "${local.name}-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ─── Security Groups ──────────────────────────────────────────────────────────

# Intentional vuln: SSH and HTTP open to the world
resource "aws_security_group" "dvwa" {
  name        = "${local.name}-dvwa-sg"
  description = "DVWA web server - intentionally permissive"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from anywhere — intentional vuln"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP-alt"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${local.name}-dvwa-sg" }
}

# ─── Overprivileged IAM Role ──────────────────────────────────────────────────

# Intentional vuln: AdministratorAccess on instance role
resource "aws_iam_role" "overprivileged" {
  name = "${local.name}-overprivileged-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.overprivileged.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "overprivileged" {
  name = "${local.name}-overprivileged-profile"
  role = aws_iam_role.overprivileged.name
}

# ─── EC2 Instance (DVWA) ─────────────────────────────────────────────────────

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Intentional vuln: IMDSv1 not disabled (hop_limit=2, no token required)
resource "aws_instance" "dvwa" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.dvwa.id]
  iam_instance_profile   = aws_iam_instance_profile.overprivileged.name

  # Intentional vuln: IMDSv1 enabled (no token required to access credentials)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"  # IMDSv1 allowed
    http_put_response_hop_limit = 2
  }

  # Intentional vuln: EBS not encrypted
  root_block_device {
    volume_size = 20
    encrypted   = false
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y apache2 php php-mysql mysql-client docker.io awscli curl

    # Install DVWA via Docker
    docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa

    # Expose SA credentials on a well-known path
    mkdir -p /var/www/html
    TOKEN=$(curl -s http://169.254.169.254/latest/api/token \
      -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)
    if [ -n "$TOKEN" ]; then
      ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
        http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true)
      curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE" \
        > /var/www/html/instance-credentials.json 2>/dev/null || true
    fi

    cat > /var/www/html/info.php << 'PHPEOF'
    <?php phpinfo(); ?>
    PHPEOF
  EOF
  )

  tags = { Name = "${local.name}-dvwa" }
}

# ─── Public S3 Bucket with Credentials ───────────────────────────────────────

resource "aws_s3_bucket" "vulnerable" {
  bucket        = "${local.name}-public-${local.suffix}"
  force_destroy = true
  tags          = { Name = "${local.name}-public-bucket" }
}

# Intentional vuln: public access block disabled
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Intentional vuln: bucket policy allows public GetObject
resource "aws_s3_bucket_policy" "public_read" {
  bucket     = aws_s3_bucket.vulnerable.id
  depends_on = [aws_s3_bucket_public_access_block.vulnerable]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.vulnerable.arn}/*"
    }]
  })
}

# Intentional vuln: no versioning, no encryption, no logging
resource "aws_s3_object" "db_creds" {
  bucket       = aws_s3_bucket.vulnerable.id
  key          = "secrets/database-credentials.json"
  content_type = "application/json"
  content = jsonencode({
    host     = "db.internal"
    port     = 3306
    database = "app"
    username = "admin"
    password = var.db_password
    note     = "Production DB credentials — do not share"
  })
  depends_on = [aws_s3_bucket_policy.public_read]
}

resource "aws_s3_object" "ssh_key" {
  bucket       = aws_s3_bucket.vulnerable.id
  key          = "keys/id_rsa"
  content_type = "text/plain"
  content      = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA... (sample key for lab)\n-----END RSA PRIVATE KEY-----\n"
  depends_on   = [aws_s3_bucket_policy.public_read]
}

# ─── Lambda Function (SSRF + RCE + Env Dump) ─────────────────────────────────

resource "aws_iam_role" "lambda_role" {
  name = "${local.name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Intentional vuln: Lambda also has AdministratorAccess
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_code"
  output_path = "${path.module}/.build/vulnerable_lambda.zip"
}

resource "aws_lambda_function" "vulnerable" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${local.name}-vulnerable-fn"
  role             = aws_iam_role.lambda_role.arn
  handler          = "handler.handler"
  runtime          = "python3.11"
  timeout          = 30

  # Intentional vuln: hardcoded credentials in environment variables
  environment {
    variables = {
      DB_URL       = local.db_url
      API_KEY      = local.api_key
      SECRET_TOKEN = local.secret_token
      ENVIRONMENT  = "production"
    }
  }

  # Intentional vuln: no KMS encryption on env vars
  # kms_key_arn not set

  tags = { Name = "${local.name}-vulnerable-fn" }
}

# Intentional vuln: public function URL with no authentication
resource "aws_lambda_function_url" "vulnerable" {
  function_name      = aws_lambda_function.vulnerable.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST"]
  }
}

# ─── Secrets Manager (accessible via overprivileged role) ─────────────────────

resource "aws_secretsmanager_secret" "app_secret" {
  name                    = "${local.name}/app-credentials"
  description             = "Application credentials — intentionally overly accessible"
  recovery_window_in_days = 0  # Intentional: instant deletion, no recovery window
  # Intentional vuln: no KMS key (uses default AWS-managed key)
}

resource "aws_secretsmanager_secret_version" "app_secret" {
  secret_id = aws_secretsmanager_secret.app_secret.id
  secret_string = jsonencode({
    username     = "admin"
    password     = var.db_password
    api_key      = local.api_key
    private_key  = "-----BEGIN RSA PRIVATE KEY-----\nlab-key-content\n-----END RSA PRIVATE KEY-----"
  })
}

# Intentional vuln: resource-based policy allows any principal in the account
resource "aws_secretsmanager_secret_policy" "overly_permissive" {
  secret_arn = aws_secretsmanager_secret.app_secret.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowAnyPrincipalInAccount"
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      }
      Action   = "secretsmanager:GetSecretValue"
      Resource = "*"
    }]
  })
}

# ─── No CloudTrail ────────────────────────────────────────────────────────────
# Intentional vuln: no CloudTrail trail deployed — attacker activity not logged
# (Absence of CloudTrail is a finding StratusAI will detect)
