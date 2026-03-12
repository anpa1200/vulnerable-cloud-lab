# ============================================================
# GCP Vulnerable Cloud Lab — Intentionally Misconfigured
# WARNING: Deploy only in isolated test environments
# ============================================================

# Random suffix for globally-unique resource names
resource "random_id" "suffix" {
  byte_length = 4
}

# ============================================================
# Enable Required APIs
# ============================================================
resource "google_project_service" "required_apis" {
  for_each = toset([
    "compute.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "secretmanager.googleapis.com",
    "container.googleapis.com",
    "run.googleapis.com",
    "cloudfunctions.googleapis.com",
    "cloudbuild.googleapis.com",
  ])

  service            = each.value
  project            = var.project_id
  disable_on_destroy = false
}

# ============================================================
# Networking
# ============================================================
resource "google_compute_network" "vulnerable_vpc" {
  name                    = "vulnerable-vpc-${random_id.suffix.hex}"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required_apis]
}

resource "google_compute_subnetwork" "public_subnet" {
  name          = "public-subnet-${random_id.suffix.hex}"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.vulnerable_vpc.id
}

# Private subnet — target for lateral movement exercises
resource "google_compute_subnetwork" "private_subnet" {
  name                     = "private-subnet-${random_id.suffix.hex}"
  ip_cidr_range            = "10.0.2.0/24"
  region                   = var.region
  network                  = google_compute_network.vulnerable_vpc.id
  private_ip_google_access = true
}

# ============================================================
# Firewall Rules — Intentionally Permissive
# ============================================================

# Allow all TCP/UDP/ICMP internally — no segmentation
resource "google_compute_firewall" "allow_all_internal" {
  name    = "allow-all-internal-${random_id.suffix.hex}"
  network = google_compute_network.vulnerable_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["vulnerable"]
}

# Expose web services to the world
resource "google_compute_firewall" "allow_http_https" {
  name    = "allow-http-https-${random_id.suffix.hex}"
  network = google_compute_network.vulnerable_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8080", "8443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-server"]
}

# SSH open to the world — vulnerable by design
resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh-${random_id.suffix.hex}"
  network = google_compute_network.vulnerable_vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["web-server", "vulnerable"]
}

# ============================================================
# Overprivileged Service Account
# ============================================================
resource "google_service_account" "overprivileged_sa" {
  account_id   = "overprivileged-sa-${random_id.suffix.hex}"
  display_name = "Overprivileged Service Account"
  description  = "Intentionally overprivileged for pentest lab"

  depends_on = [google_project_service.required_apis]
}

# Grant Owner + Storage/Secret/Compute/IAM admin — way too much
resource "google_project_iam_member" "overprivileged_roles" {
  for_each = toset([
    "roles/owner",
    "roles/storage.admin",
    "roles/secretmanager.admin",
    "roles/compute.admin",
    "roles/iam.securityAdmin",
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.overprivileged_sa.email}"
}

# Generate and expose a service account key
resource "google_service_account_key" "exposed_key" {
  service_account_id = google_service_account.overprivileged_sa.name
  public_key_type    = "TYPE_X509_PEM_FILE"
}

# ============================================================
# Secret Manager — key stored but also exposed elsewhere
# ============================================================
resource "google_secret_manager_secret" "sa_key_secret" {
  secret_id = "exposed-sa-key-${random_id.suffix.hex}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.required_apis]
}

resource "google_secret_manager_secret_version" "sa_key_version" {
  secret      = google_secret_manager_secret.sa_key_secret.id
  secret_data = base64decode(google_service_account_key.exposed_key.private_key)
}

# ============================================================
# Storage Bucket — Publicly accessible with sensitive data
# ============================================================
resource "google_storage_bucket" "vulnerable_bucket" {
  name          = "vulnerable-bucket-${random_id.suffix.hex}"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = false

  # Intentionally no public access prevention
  public_access_prevention = "inherited"

  depends_on = [google_project_service.required_apis]
}

# Make bucket world-readable
resource "google_storage_bucket_iam_member" "bucket_public_read" {
  bucket = google_storage_bucket.vulnerable_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

# Upload fake database credentials as a "sensitive" file
resource "google_storage_bucket_object" "sensitive_credentials" {
  name   = "secrets/database-credentials.json"
  bucket = google_storage_bucket.vulnerable_bucket.name
  content = jsonencode({
    db_host     = "internal-db-${random_id.suffix.hex}"
    db_user     = "admin"
    db_password = "SuperSecret123!"
    api_key     = "sk_live_${random_id.suffix.hex}"
    note        = "This file is intentionally exposed for pentest lab purposes"
  })
}

# Upload exposed SSH private key (fake)
resource "google_storage_bucket_object" "exposed_ssh_key" {
  name    = "keys/id_rsa"
  bucket  = google_storage_bucket.vulnerable_bucket.name
  content = <<-EOF
    -----BEGIN OPENSSH PRIVATE KEY-----
    FAKE_KEY_FOR_PENTEST_LAB_DO_NOT_USE_IN_PRODUCTION
    This is a fake key uploaded intentionally for security testing.
    -----END OPENSSH PRIVATE KEY-----
  EOF
}

# ============================================================
# Cloud Function source code archive
# ============================================================
data "archive_file" "function_zip" {
  type        = "zip"
  output_path = "${path.module}/function_code.zip"
  source_dir  = "${path.module}/function_code"
}

resource "google_storage_bucket_object" "function_code_zip" {
  name   = "function-code-${data.archive_file.function_zip.output_md5}.zip"
  bucket = google_storage_bucket.vulnerable_bucket.name
  source = data.archive_file.function_zip.output_path
}

# ============================================================
# Web Server — DVWA + info disclosure page
# ============================================================
resource "google_compute_instance" "web_server" {
  name         = "web-server-${random_id.suffix.hex}"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 20
    }
  }

  network_interface {
    network    = google_compute_network.vulnerable_vpc.name
    subnetwork = google_compute_subnetwork.public_subnet.name

    access_config {
      # Assigns ephemeral public IP
    }
  }

  tags = ["web-server", "vulnerable"]

  metadata = {
    # Expose service account key in instance metadata — intentional vulnerability
    "sa-key" = base64decode(google_service_account_key.exposed_key.private_key)

    startup-script = <<-SCRIPT
      #!/bin/bash
      set -e

      # Write exposed SA key to disk
      echo '${base64decode(google_service_account_key.exposed_key.private_key)}' > /tmp/sa-key.json
      chmod 644 /tmp/sa-key.json

      # Update and install DVWA dependencies
      apt-get update -q
      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nginx php-fpm php-cli php-mysql php-gd php-curl php-xml php-mbstring php-zip \
        mariadb-server mariadb-client git unzip curl

      systemctl enable mariadb nginx php7.4-fpm
      systemctl start mariadb nginx php7.4-fpm

      # Configure MariaDB for DVWA
      mysql -e "CREATE DATABASE IF NOT EXISTS dvwa;"
      mysql -e "CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd';"
      mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
      mysql -e "FLUSH PRIVILEGES;"

      # Deploy DVWA
      cd /var/www/html
      rm -rf *
      git clone https://github.com/digininja/DVWA.git .

      cp config/config.inc.php.dist config/config.inc.php
      sed -i "s/\$_DVWA\[ 'db_user' \] = 'root';/\$_DVWA[ 'db_user' ] = 'dvwa';/" config/config.inc.php
      sed -i "s/\$_DVWA\[ 'db_password' \] = 'p@ssw0rd';/\$_DVWA[ 'db_password' ] = 'p@ssw0rd';/" config/config.inc.php
      sed -i "s/\$_DVWA\[ 'default_security_level' \] = 'impossible';/\$_DVWA[ 'default_security_level' ] = 'low';/" config/config.inc.php

      chown -R www-data:www-data /var/www/html
      chmod -R 755 /var/www/html
      chmod 777 /var/www/html/hackable/uploads/ 2>/dev/null || true
      chmod 777 /var/www/html/config

      # Information disclosure page — exposes Cloud Function / Cloud Run URLs
      cat > /var/www/html/info.php <<'INFOPHP'
      <?php
      // INTENTIONAL INFORMATION DISCLOSURE — pentest lab
      ?><!DOCTYPE html>
      <html>
      <head>
        <title>Internal Services</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
          .box { background: white; padding: 20px; border-radius: 6px; margin: 16px 0; }
          h1 { color: #333; }
          .url { font-family: monospace; background: #f0f0f0; padding: 4px 8px; }
        </style>
      </head>
      <body>
        <h1>Internal Services — Development</h1>
        <div class="box">
          <h3>Cloud Function</h3>
          <div class="url">${google_cloudfunctions_function.vulnerable_function.https_trigger_url}</div>
          <small>Endpoints: ?cmd= / ?url= / ?env= / ?secret=</small>
        </div>
        <div class="box">
          <h3>Cloud Run API</h3>
          <div class="url">${google_cloud_run_service.vulnerable_api.status[0].url}</div>
        </div>
        <div class="box">
          <h3>Storage Bucket</h3>
          <div class="url">gs://${google_storage_bucket.vulnerable_bucket.name}</div>
        </div>
        <div class="box">
          <h3>Service Account Key</h3>
          <div class="url">cat /tmp/sa-key.json</div>
        </div>
        <p><a href="/">← DVWA</a></p>
      </body>
      </html>
      INFOPHP

      # Nginx config for PHP
      cat > /etc/nginx/sites-available/default <<'NGINX'
      server {
        listen 80 default_server;
        root /var/www/html;
        index index.php index.html;
        location / { try_files $uri $uri/ =404; }
        location ~ \.php$ {
          include snippets/fastcgi-php.conf;
          fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
        }
        location ~ /\.ht { deny all; }
      }
      NGINX

      systemctl restart nginx php7.4-fpm

      echo "=== DVWA setup complete ==="
      echo "URL: http://$(curl -s ifconfig.me)/"
      echo "Credentials: admin / password"
      echo "Info page: http://$(curl -s ifconfig.me)/info.php"
    SCRIPT
  }

  service_account {
    email  = google_service_account.overprivileged_sa.email
    scopes = ["cloud-platform"]
  }

  depends_on = [google_project_service.required_apis]
}

# ============================================================
# Internal Database Server — no public IP
# ============================================================
resource "google_compute_instance" "db_server" {
  name         = "db-server-${random_id.suffix.hex}"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
      size  = 20
    }
  }

  network_interface {
    network    = google_compute_network.vulnerable_vpc.name
    subnetwork = google_compute_subnetwork.private_subnet.name
    # No access_config = no public IP
  }

  tags = ["database", "vulnerable"]

  metadata = {
    startup-script = <<-SCRIPT
      #!/bin/bash
      apt-get update -q
      DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server
      systemctl enable mariadb
      systemctl start mariadb

      # Vulnerable: bind to all interfaces with weak credentials
      sed -i 's/bind-address\s*=.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf

      mysql -e "CREATE DATABASE app_db;"
      mysql -e "CREATE USER 'admin'@'%' IDENTIFIED BY 'SuperSecret123!';"
      mysql -e "GRANT ALL PRIVILEGES ON app_db.* TO 'admin'@'%';"
      mysql -e "FLUSH PRIVILEGES;"
      systemctl restart mariadb
    SCRIPT
  }

  depends_on = [google_project_service.required_apis]
}

# ============================================================
# Cloud Run — Vulnerable API with credentials in env vars
# ============================================================
resource "google_cloud_run_service" "vulnerable_api" {
  name     = "vulnerable-api-${random_id.suffix.hex}"
  location = var.region

  template {
    spec {
      service_account_name = google_service_account.overprivileged_sa.email

      containers {
        image = "gcr.io/cloudrun/hello"

        # Credentials hardcoded in environment variables — intentional
        env {
          name  = "DATABASE_URL"
          value = "mysql://admin:SuperSecret123!@internal-db-${random_id.suffix.hex}:3306/app_db"
        }
        env {
          name  = "API_KEY"
          value = "sk_live_${random_id.suffix.hex}"
        }
        env {
          name  = "SECRET_TOKEN"
          value = "s3cr3t_t0k3n_${random_id.suffix.hex}"
        }
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.required_apis]
}

# Make Cloud Run publicly accessible — no authentication
resource "google_cloud_run_service_iam_member" "run_public_access" {
  service  = google_cloud_run_service.vulnerable_api.name
  location = google_cloud_run_service.vulnerable_api.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ============================================================
# Cloud Function — SSRF + Command Injection + Env Disclosure
# ============================================================
resource "google_cloudfunctions_function" "vulnerable_function" {
  name        = "vulnerable-fn-${random_id.suffix.hex}"
  description = "Intentionally vulnerable function — SSRF, RCE, secret disclosure"
  runtime     = "python39"
  region      = var.region

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.vulnerable_bucket.name
  source_archive_object = google_storage_bucket_object.function_code_zip.name

  trigger_http = true
  entry_point  = "vulnerable_handler"

  service_account_email = google_service_account.overprivileged_sa.email

  environment_variables = {
    SECRET_KEY      = "exposed-secret-${random_id.suffix.hex}"
    DB_PASSWORD     = "SuperSecret123!"
    INTERNAL_API_TOKEN = "int_tok_${random_id.suffix.hex}"
  }

  depends_on = [
    google_project_service.required_apis,
    google_storage_bucket_object.function_code_zip,
  ]
}

# No authentication — anyone can invoke
resource "google_cloudfunctions_function_iam_member" "function_public_access" {
  project        = var.project_id
  region         = var.region
  cloud_function = google_cloudfunctions_function.vulnerable_function.name
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}
