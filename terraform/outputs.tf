output "project_id" {
  description = "GCP Project ID"
  value       = var.project_id
}

output "region" {
  description = "GCP Region"
  value       = var.region
}

output "zone" {
  description = "GCP Zone"
  value       = var.zone
}

output "web_server_ip" {
  description = "Public IP of the DVWA web server"
  value       = google_compute_instance.web_server.network_interface[0].access_config[0].nat_ip
}

output "web_server_name" {
  description = "Name of the web server instance"
  value       = google_compute_instance.web_server.name
}

output "db_server_name" {
  description = "Name of the internal database server"
  value       = google_compute_instance.db_server.name
}

output "db_server_internal_ip" {
  description = "Internal IP of the database server"
  value       = google_compute_instance.db_server.network_interface[0].network_ip
  sensitive   = true
}

output "vulnerable_bucket_name" {
  description = "Name of the publicly accessible storage bucket"
  value       = google_storage_bucket.vulnerable_bucket.name
}

output "vulnerable_bucket_url" {
  description = "Public URL of the sensitive credentials file"
  value       = "https://storage.googleapis.com/${google_storage_bucket.vulnerable_bucket.name}/secrets/database-credentials.json"
}

output "cloud_run_url" {
  description = "URL of the vulnerable Cloud Run service"
  value       = google_cloud_run_service.vulnerable_api.status[0].url
}

output "cloud_function_url" {
  description = "URL of the vulnerable Cloud Function (SSRF / RCE / env disclosure)"
  value       = google_cloudfunctions_function.vulnerable_function.https_trigger_url
}

output "overprivileged_sa_email" {
  description = "Email of the overprivileged service account"
  value       = google_service_account.overprivileged_sa.email
}

output "dvwa_url" {
  description = "DVWA login URL (admin / password)"
  value       = "http://${google_compute_instance.web_server.network_interface[0].access_config[0].nat_ip}/"
}

output "info_page_url" {
  description = "Information disclosure page exposing all internal service URLs"
  value       = "http://${google_compute_instance.web_server.network_interface[0].access_config[0].nat_ip}/info.php"
}

output "secret_manager_name" {
  description = "Secret Manager secret containing the exposed SA key"
  value       = google_secret_manager_secret.sa_key_secret.secret_id
}

output "lab_summary" {
  description = "Complete summary of all vulnerable resources"
  value = <<-EOT
    ============================================================
     GCP Vulnerable Cloud Lab — Attack Surface Summary
    ============================================================
     Web Server (DVWA):  http://${google_compute_instance.web_server.network_interface[0].access_config[0].nat_ip}/
     DVWA Credentials:   admin / password
     Info Disclosure:    http://${google_compute_instance.web_server.network_interface[0].access_config[0].nat_ip}/info.php
     Cloud Function:     ${google_cloudfunctions_function.vulnerable_function.https_trigger_url}
     Cloud Run:          ${google_cloud_run_service.vulnerable_api.status[0].url}
     Public Bucket:      gs://${google_storage_bucket.vulnerable_bucket.name}
     Secret Creds:       https://storage.googleapis.com/${google_storage_bucket.vulnerable_bucket.name}/secrets/database-credentials.json
     SA Key on Disk:     /tmp/sa-key.json (on web server)
     Overprivileged SA:  ${google_service_account.overprivileged_sa.email}
    ============================================================
     WARNING: Destroy with `terraform destroy` when finished!
    ============================================================
  EOT
}
