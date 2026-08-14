# Deployment Guide — Step by Step

Follow in exact order. Every command is copy-paste ready.

---

## Prerequisites (do these once)

- AWS account (free tier)
- AWS CLI installed and configured (`aws configure`)
- Terraform installed (`terraform -version`)
- Ansible installed (`ansible --version`)
- Git installed

---

## Step 1 — Generate SSH Key

```bash
ssh-keygen -t ed25519 -f ~/.ssh/threat-intel -C "threat-intel-platform"
# Press Enter twice (no passphrase for simplicity)

# View your public key — you'll need this
cat ~/.ssh/threat-intel.pub
```

---

## Step 2 — Get Your Home IP

```bash
curl https://checkip.amazonaws.com
# e.g. 103.xx.xx.xx
# You'll use this as YOUR_HOME_IP/32 in terraform.tfvars
```

---

## Step 3 — Terraform (provision AWS infra)

```bash
cd terraform

# Copy and edit tfvars
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars
# Set: my_ip = "103.xx.xx.xx/32"   ← your IP from Step 2

# Initialise
terraform init

# Preview what will be created
terraform plan

# Create everything (takes ~2 minutes)
terraform apply
# type: yes

# Note the outputs:
# public_ip   = "xx.xx.xx.xx"   ← your permanent IP
# app_url     = "http://xx.xx.xx.xx:5000"
# ssh_command = "ssh -i ~/.ssh/threat-intel ubuntu@xx.xx.xx.xx"
```

---

## Step 4 — Set Up GitHub Secrets

In your GitHub repo → Settings → Secrets → Actions → New secret:

| Secret Name | Value |
|---|---|
| `EC2_HOST` | your Elastic IP from terraform output |
| `EC2_SSH_KEY` | contents of `~/.ssh/threat-intel` (private key) |
| `DB_PASS` | any strong password e.g. `Str0ngP@ss!23` |
| `OTX_API_KEY` | your free key from otx.alienvault.com (optional) |

```bash
# Get private key contents:
cat ~/.ssh/threat-intel
# Copy everything including -----BEGIN and -----END lines
```

---

## Step 5 — Ansible (configure EC2 and deploy app)

```bash
cd ../ansible

# Edit inventory with your Elastic IP
nano inventory.ini
# Replace YOUR_ELASTIC_IP with the IP from terraform output

# Test SSH connection first
ssh -i ~/.ssh/threat-intel ubuntu@YOUR_ELASTIC_IP

# Run deployment playbook
DB_PASS="Str0ngP@ss!23" ansible-playbook -i inventory.ini deploy.yml

# This will:
# ✓ Install Docker on EC2
# ✓ Copy all project files
# ✓ Write .env file
# ✓ Build and start all containers
# ✓ Configure UFW firewall
# ✓ Set up systemd auto-start service
```

---

## Step 6 — Verify Everything is Running

```bash
# SSH into server
ssh -i ~/.ssh/threat-intel ubuntu@YOUR_ELASTIC_IP

# Check all containers
docker ps
# Should see: app, postgres, redis, prometheus, grafana, node-exporter

# Check app logs
docker logs threat-intel-app --tail 50

# Check feed sync started
docker logs threat-intel-app | grep -E "Feodo|URLhaus|OTX|Sync"
```

**Open in browser:**
- App dashboard: `http://YOUR_IP:5000`
- Grafana: `http://YOUR_IP:3000` (login: admin / your GRAFANA_PASS)
- Metrics: `http://YOUR_IP:5000/metrics`

---

## Step 7 — Set Up Wazuh SIEM (optional but recommended for cybersecurity resume)

```bash
# On EC2 — install Wazuh agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" \
  > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install -y wazuh-agent

# Configure to report to Wazuh cloud (free account at cloud.wazuh.com)
nano /var/ossec/etc/ossec.conf
# Set your Wazuh manager IP/cloud endpoint

# Copy custom rules
cp /opt/threat-intel/wazuh/custom-rules.xml /var/ossec/etc/rules/local_rules.xml

# Start agent
systemctl enable wazuh-agent && systemctl start wazuh-agent
```

---

## Step 8 — Enable GuardDuty (free 30-day trial, then ~$1-3/month)

```bash
# Via AWS CLI
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES \
  --region ap-south-1

# Or: AWS Console → GuardDuty → Enable GuardDuty
```

---

## Step 9 — Test the CI/CD Pipeline

```bash
# Make a small change to trigger the pipeline
echo "# test" >> README.md
git add . && git commit -m "test: trigger CI pipeline"
git push origin main

# Watch pipeline at: GitHub → Actions tab
# Should see: Security Gates → Build → Deploy → Health Check
```

---

## Step 10 — Update Your Resume

Add this to your resume:

**Cybersecurity resume:**
> Threat Intelligence Platform — Live IOC aggregator pulling from abuse.ch, Feodo Tracker, AlienVault OTX; public REST API (/api/check); Wazuh SIEM with 6 custom MITRE ATT&CK-mapped rules; GuardDuty enabled; DevSecOps CI/CD with Checkov, Trivy, GitLeaks, Semgrep gates.

**DevOps resume:**
> Threat Intelligence Platform — Python/Flask on EC2, PostgreSQL + Redis, Terraform-provisioned VPC/EC2/EIP, Ansible deployment automation, Prometheus/Grafana observability, GitHub Actions CI/CD with 4 security gates, Docker multi-stage build, systemd auto-restart.

---

## Troubleshooting

**App not starting:**
```bash
docker logs threat-intel-app
# Usually: DB not ready yet — wait 30s and try again
```

**Postgres connection refused:**
```bash
docker exec -it threat-intel-db psql -U sejal -d threatintel
# If this works, postgres is fine — check DB_HOST env var in app
```

**Checkov failing in CI:**
```bash
# Run locally to see exactly what's failing
pip install checkov
checkov -d terraform/ --framework terraform
```

**Port not accessible:**
```bash
# Check security group in AWS Console
# Check UFW on server:
sudo ufw status
```
