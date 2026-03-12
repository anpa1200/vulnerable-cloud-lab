output "dvwa_public_ip" {
  description = "DVWA web server public IP"
  value       = aws_instance.dvwa.public_ip
}

output "dvwa_url" {
  description = "DVWA web application URL"
  value       = "http://${aws_instance.dvwa.public_ip}/"
}

output "dvwa_info_php" {
  description = "phpinfo() page (info disclosure)"
  value       = "http://${aws_instance.dvwa.public_ip}/info.php"
}

output "dvwa_credentials_json" {
  description = "Instance IAM credentials exposed via web server (IMDSv1 dump)"
  value       = "http://${aws_instance.dvwa.public_ip}/instance-credentials.json"
}

output "lambda_url" {
  description = "Vulnerable Lambda function URL (public, no auth)"
  value       = aws_lambda_function_url.vulnerable.function_url
}

output "lambda_ssrf_example" {
  description = "SSRF example — fetch IMDSv1 credentials from Lambda"
  value       = "${aws_lambda_function_url.vulnerable.function_url}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}

output "lambda_rce_example" {
  description = "RCE example"
  value       = "${aws_lambda_function_url.vulnerable.function_url}?cmd=id"
}

output "s3_bucket_name" {
  description = "Public S3 bucket name"
  value       = aws_s3_bucket.vulnerable.bucket
}

output "s3_public_db_creds" {
  description = "Publicly accessible database credentials"
  value       = "https://${aws_s3_bucket.vulnerable.bucket}.s3.amazonaws.com/secrets/database-credentials.json"
}

output "s3_public_ssh_key" {
  description = "Publicly accessible SSH private key"
  value       = "https://${aws_s3_bucket.vulnerable.bucket}.s3.amazonaws.com/keys/id_rsa"
}

output "secrets_manager_arn" {
  description = "Secrets Manager secret ARN"
  value       = aws_secretsmanager_secret.app_secret.arn
}

output "overprivileged_role_arn" {
  description = "IAM role with AdministratorAccess (attached to EC2 and Lambda)"
  value       = aws_iam_role.overprivileged.arn
}

output "aws_account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS region"
  value       = var.aws_region
}

output "attack_surface_summary" {
  description = "Attack surface overview"
  value = <<-EOT
    ============================================================
     Vulnerable AWS Lab — Attack Surface Summary
    ============================================================
     DVWA Web Server:   http://${aws_instance.dvwa.public_ip}/
     DVWA Credentials:  admin / password
     Info Disclosure:   http://${aws_instance.dvwa.public_ip}/info.php
     IMDS Credentials:  http://${aws_instance.dvwa.public_ip}/instance-credentials.json

     Lambda Function:   ${aws_lambda_function_url.vulnerable.function_url}
     Lambda SSRF:       ?url=http://169.254.169.254/latest/meta-data/
     Lambda RCE:        ?cmd=id
     Lambda Env Dump:   ?env=1

     Public Bucket:     s3://${aws_s3_bucket.vulnerable.bucket}
     DB Credentials:    .../secrets/database-credentials.json (world-readable)
     SSH Private Key:   .../keys/id_rsa (world-readable)

     Secret ARN:        ${aws_secretsmanager_secret.app_secret.arn}
     Overprivileged SA: ${aws_iam_role.overprivileged.arn}
     Account:           ${data.aws_caller_identity.current.account_id} (${var.aws_region})
    ============================================================
     WARNING: Destroy with `terraform destroy` when finished!
    ============================================================
  EOT
}
