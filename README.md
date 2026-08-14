# 🛡 Threat Intelligence Platform

> Live threat feed aggregator with DevSecOps CI/CD, SIEM monitoring, and Prometheus/Grafana observability.

**Live Demo:** http://YOUR_ELASTIC_IP:5000  
**Grafana Dashboard:** http://YOUR_ELASTIC_IP:3000  
**API:** `GET /api/check?ip=1.2.3.4`

---

## What It Does

Aggregates Indicators of Compromise (IOCs) from free public threat feeds in real time:

| Source | Type | Volume |
|---|---|---|
| [Feodo Tracker](https://feodotracker.abuse.ch) | Botnet C2 IPs | ~500 IPs |
| [abuse.ch URLhaus](https://urlhaus.abuse.ch) | Malicious URLs | ~200 latest |
| [AlienVault OTX](https://otx.alienvault.com) | Mixed IOCs | ~varies |

Exposes a public dashboard and REST API to check whether an IP, domain, or URL is known-malicious.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        GitHub Actions                        │
│   Checkov → GitLeaks → Semgrep → Trivy → Deploy to EC2      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │    EC2 t2.micro      │  ← Terraform provisioned
                    │   (Ubuntu 22.04)     │  ← Ansible configured
                    │                     │
                    │  ┌───────────────┐  │
                    │  │  Flask App    │  │  ← :5000
                    │  │  (Gunicorn)   │  │
                    │  └──────┬────────┘  │
                    │         │           │
                    │  ┌──────▼────────┐  │
                    │  │  PostgreSQL   │  │  ← IOC storage
                    │  └───────────────┘  │
                    │  ┌───────────────┐  │
                    │  │  Redis cache  │  │  ← 1hr TTL on checks
                    │  └───────────────┘  │
                    │  ┌───────────────┐  │
                    │  │  Prometheus   │  │  ← :9090
                    │  └───────────────┘  │
                    │  ┌───────────────┐  │
                    │  │   Grafana     │  │  ← :3000 (public)
                    │  └───────────────┘  │
                    │  ┌───────────────┐  │
                    │  │  Wazuh Agent  │  │  ← SIEM monitoring
                    │  └───────────────┘  │
                    └─────────────────────┘
```

---

## Tech Stack

**Application:** Python, Flask, Gunicorn, PostgreSQL, Redis  
**Infrastructure:** AWS EC2 (t2.micro), VPC, Security Groups, Elastic IP — Terraform  
**Configuration:** Ansible (deploy + firewall + systemd service)  
**CI/CD:** GitHub Actions  
**Security Gates:** Checkov (IaC), GitLeaks (secrets), Semgrep (SAST), Trivy (container CVEs)  
**Monitoring:** Prometheus, Grafana, Node Exporter  
**Security Monitoring:** Wazuh SIEM (6 custom rules), AWS GuardDuty, CloudTrail  
**Containerisation:** Docker, Docker Compose (multi-stage build)

---

## DevSecOps Pipeline

Every push to `main` runs through 4 security gates before deployment:

```
git push
    │
    ▼
┌─────────────────────────────────┐
│ 1. Checkov — Terraform IaC scan │  ← fails on HIGH misconfigs
│ 2. GitLeaks — secret detection  │  ← fails if secrets in code
│ 3. Semgrep — SAST (Python)      │  ← fails on code vulnerabilities
│ 4. Trivy — Docker image CVEs    │  ← fails on HIGH/CRITICAL CVEs
└────────────────┬────────────────┘
                 │ all pass
                 ▼
         Deploy to EC2
         Health check /health
```

---

## API

```bash
# Check an IP
curl "http://YOUR_IP:5000/api/check?ip=185.220.101.1"

# Check a domain
curl "http://YOUR_IP:5000/api/check?domain=evil-domain.com"

# Check a URL
curl "http://YOUR_IP:5000/api/check?url=http://bad.site/malware.exe"

# Stats
curl "http://YOUR_IP:5000/api/stats"
```

**Response (malicious):**
```json
{
  "indicator": "185.220.101.1",
  "malicious": true,
  "hits": 2,
  "max_confidence": 90,
  "sources": [
    {
      "source": "feodo",
      "threat_type": "Emotet",
      "confidence": 90,
      "last_seen": "2026-08-09 10:32:00"
    }
  ]
}
```

---

## SIEM — Custom Wazuh Rules

6 custom detection rules covering:

| Rule | MITRE ATT&CK | Alert Level |
|---|---|---|
| SSH brute force (5 failures / 2 min) | T1110.001 | High (10) |
| Root SSH login | T1078.003 | Critical (12) |
| Cron modification (persistence) | T1053.003 | Medium (8) |
| Docker socket access | T1611 | High (9) |
| App 5xx error spike | — | Medium (6) |
| Outbound C2 connection | T1071 | Critical (14) |

---

## How to Run Locally

```bash
git clone https://github.com/Sejalthakur17/threat-intel-platform
cd threat-intel-platform

# create .env
cp .env.example .env
# edit .env with your DB_PASS

docker compose up --build
# App:      http://localhost:5000
# Grafana:  http://localhost:3000
# Metrics:  http://localhost:5000/metrics
```

---

## How to Deploy to AWS (Free Tier)

Full step-by-step in [docs/deployment-guide.md](docs/deployment-guide.md)

**Quick version:**
```bash
# 1. Generate SSH key
ssh-keygen -t ed25519 -f ~/.ssh/threat-intel

# 2. Terraform
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars with your IP
terraform init && terraform apply

# 3. Ansible
cd ../ansible
# edit inventory.ini with your Elastic IP
ansible-playbook -i inventory.ini deploy.yml
```

---

## Cost (AWS Free Tier)

| Resource | Free Tier | Monthly |
|---|---|---|
| EC2 t2.micro | 750 hrs/month | $0 |
| EBS 20GB gp2 | 30GB included | $0 |
| Data transfer | 15GB out | ~$0 |
| Elastic IP (attached) | Free | $0 |
| **Total** | | **~$0** |

---

## Project Structure

```
threat-intel-platform/
├── app/
│   ├── app.py              # Flask app — feeds, API, metrics
│   ├── requirements.txt
│   ├── Dockerfile          # multi-stage build
│   └── templates/
│       └── index.html      # live dashboard
├── terraform/
│   ├── main.tf             # VPC, EC2, SG, EIP
│   └── variables.tf
├── ansible/
│   ├── deploy.yml          # full deployment playbook
│   └── inventory.ini
├── prometheus/
│   └── prometheus.yml
├── grafana/
│   ├── dashboards/         # pre-built dashboard JSON
│   └── datasources/
├── wazuh/
│   └── custom-rules.xml    # 6 custom SIEM rules
├── .github/workflows/
│   └── deploy.yml          # DevSecOps CI/CD pipeline
└── docker-compose.yml
```

---

## Author

**Sejal Thakur** — Cloud Security & DevOps Engineer  
[LinkedIn](https://www.linkedin.com/in/sejalthakurr/) · [GitHub](https://github.com/Sejalthakur17) · [Portfolio](https://sejalthakur17.github.io/portfolio/)
