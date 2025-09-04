# 🔍 OpenSearch Centralized Log Server

<div align="center">

![OpenSearch Stack](https://img.shields.io/badge/OpenSearch-2.x-005EB8?style=for-the-badge&logo=opensearch&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-HTTP_Server-00D084?style=for-the-badge)
![Logstash](https://img.shields.io/badge/Logstash-Processing-F5A623?style=for-the-badge&logo=logstash&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**🚀 Production-ready centralized logging platform with AI-powered analysis**

*Collect, process, and analyze logs from Linux and Windows systems with real-time security monitoring, advanced event correlation, and intelligent automation through Model Context Protocol (MCP) integration.*

[🚀 Quick Start](#-quick-start) • [✨ Features](#-features) • [🔧 Configuration](#-configuration) • [📊 Dashboards](#-dashboards) • [🛡️ Security](#️-security) • [🤝 Contributing](#-contributing)

</div>

---

## ✨ Features

### 🔍 **Multi-Platform Log Collection**
- **🐧 Linux Systems**: Syslog, auth logs, application logs, systemd journals
- **🪟 Windows Events**: Event Logs, Security Events, Application logs via Winlogbeat
- **🌐 Network Devices**: Firewalls, routers, switches, and security appliances
- **☁️ Cloud Services**: AWS CloudTrail, Azure logs, Google Cloud logging

### 📊 **Advanced Analytics Engine**
- **🔍 Real-time Search**: Sub-second query performance across billions of logs
- **📈 Time-series Analysis**: Trend detection and anomaly identification
- **🔗 Event Correlation**: Cross-system event relationship mapping
- **🎯 Custom Dashboards**: Role-based visualization and reporting

### 🤖 **AI-Powered Intelligence**
- **🧠 MCP Server**: HTTP API for AI assistant integration
- **📱 Streaming Analytics**: Handle massive datasets efficiently
- **🔮 Predictive Analysis**: Machine learning-based threat prediction
- **💬 Natural Language Queries**: SQL-like queries via REST API

### 🛡️ **Enterprise Security**
- **⚡ Real-time Threat Detection**: MITRE ATT&CK framework integration
- **🚨 Automated Alerting**: Slack/Teams/email notifications
- **🔐 Access Control**: Role-based authentication and authorization
- **📋 Compliance Reporting**: SOC 2, PCI-DSS, HIPAA ready

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Linux Logs    │    │  Windows Events │    │  Network Logs   │
│   (Syslog/TCP)  │    │  (Winlogbeat)   │    │   (UDP/TCP)     │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────▼───────────────┐
                    │        Logstash             │
                    │   (Processing Pipeline)     │
                    └─────────────┬───────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │      OpenSearch Cluster     │
                    │    (Node1 + Node2 + HA)    │
                    └─────────────┬───────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
┌─────────▼──────────┐  ┌─────────▼──────────┐  ┌─────────▼──────────┐
│   MCP HTTP Server  │  │ OpenSearch Dashboard│  │   Direct API       │
│  (AI Integration)  │  │   (Visualizations)  │  │    (REST/SQL)      │
└────────────────────┘  └────────────────────┘  └────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- **Docker** and **Docker Compose** installed
- **4GB+ RAM** recommended for optimal performance
- **Ports available**: 5601, 8000, 9200, 9600, 514, 5044

### 1. Clone and Configure
```bash
git clone <your-repository>
cd opensearch
cp .env_example .env
# Edit .env with your settings
```

### 2. Launch the Stack
```bash
# Start all services
docker-compose up -d

# Check service health
docker-compose ps
docker-compose logs -f
```

### 3. Access Services
| Service | URL | Purpose |
|---------|-----|---------|
| 🔍 OpenSearch API | https://localhost:9200 | Direct search and admin |
| 📊 Dashboards | http://localhost:5601 | Data visualization |
| 🤖 MCP Server | http://localhost:8000 | AI integration endpoint |
| 📈 Logstash API | http://localhost:9600 | Pipeline monitoring |

### 4. Test Log Collection
```bash
# Test syslog ingestion
logger "Test message from $(hostname)"

# Verify in OpenSearch
curl -k -u admin:${OPENSEARCH_INITIAL_ADMIN_PASSWORD} \
  "https://localhost:9200/logstash-logs-*/_search?pretty&size=1"
```

---

## 🔧 Configuration

### Environment Variables
All configuration is managed through environment variables. Copy `.env_example` to `.env` and customize:

```bash
# OpenSearch Cluster
OPENSEARCH_INITIAL_ADMIN_PASSWORD=your_secure_password
OS_URL=https://opensearch-node1:9200
OS_USERNAME=admin
OS_PASSWORD=your_secure_password

# MCP Server Settings
MCP_HOST=0.0.0.0
MCP_PORT=8000
MCP_PATH=/mcp

# Optional: API Key authentication
OS_API_KEY=your_api_key_here
```

### Log Source Configuration

#### 📧 **Linux Systems**
```bash
# Add to /etc/rsyslog.conf or /etc/rsyslog.d/50-logstash.conf
*.* @@YOUR_SERVER_IP:514

# For specific facilities
auth.* @@YOUR_SERVER_IP:514
kern.* @@YOUR_SERVER_IP:514
mail.* @@YOUR_SERVER_IP:514

# Restart rsyslog
sudo systemctl restart rsyslog
```

#### 🪟 **Windows Systems**
```yaml
# Install and configure Winlogbeat
# Download from: https://www.elastic.co/downloads/beats/winlogbeat

# winlogbeat.yml configuration:
winlogbeat.event_logs:
  - name: Application
    level: error, warning
  - name: Security
    event_id: 4624, 4625, 4648, 4656, 4719, 4720
  - name: System
  - name: Microsoft-Windows-Sysmon/Operational

output.logstash:
  hosts: ["YOUR_SERVER_IP:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

#### 🐳 **Docker Containers**
```yaml
# Add to your docker-compose.yml services
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    labels: "service,environment"

# Or use Filebeat for Docker logs
```

#### 🌐 **Network Devices**
```bash
# Cisco/Juniper/Fortigate syslog forwarding
logging YOUR_SERVER_IP:514

# pfSense/OPNsense
Configure System > Advanced > Logging
Remote Logging Options: YOUR_SERVER_IP:514
```

---

## 📊 Dashboards & Visualization

### Pre-built Dashboard Categories
- **🔒 Security Operations Center (SOC)**: Failed logins, privilege escalations, suspicious activities
- **💻 System Health**: CPU, memory, disk usage, service status  
- **🌐 Network Analysis**: Traffic patterns, connection monitoring, firewall events
- **📱 Application Logs**: Error rates, performance metrics, user activities
- **📋 Compliance**: Audit trails, access logs, regulatory reporting

### Sample Queries

#### OpenSearch REST API
```bash
# Search recent security events
curl -k -u admin:${PASSWORD} -X POST \
  "https://localhost:9200/logstash-logs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "query": {
      "bool": {
        "must": [
          {"range": {"@timestamp": {"gte": "now-1h"}}},
          {"match": {"syslog_program": "sshd"}}
        ]
      }
    },
    "size": 100
  }'
```

#### SQL Queries via MCP
```sql
-- Find failed SSH attempts
SELECT timestamp, source_ip, syslog_message 
FROM "logstash-logs-*" 
WHERE syslog_message LIKE '%Failed password%' 
AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
ORDER BY timestamp DESC;

-- Windows login analysis
SELECT user_name, logon_type, source_ip, COUNT(*) as login_count
FROM "windows-events-*"
WHERE event_id = 4624
  AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)
GROUP BY user_name, logon_type, source_ip
ORDER BY login_count DESC;

-- Top error producers
SELECT syslog_server, syslog_program, COUNT(*) as error_count
FROM "logstash-logs-*" 
WHERE syslog_severity <= 3
  AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY syslog_server, syslog_program
ORDER BY error_count DESC
LIMIT 20;
```

---

## 🛡️ Security Features

### 🎯 **Automated Threat Detection**
- **Brute Force Detection**: >5 failed logins in 5 minutes
- **Lateral Movement**: Unusual cross-system access patterns
- **Privilege Escalation**: `sudo`, `su`, admin group changes
- **Data Exfiltration**: Large outbound transfers or unusual access patterns
- **Malware Indicators**: Process execution anomalies, file modifications

### 📊 **Security Monitoring Rules**

#### Critical Alerts
```yaml
# Failed Authentication Attempts
- Query: syslog_message:"Failed password" OR event_id:4625
- Threshold: >5 occurrences in 5 minutes
- Action: Immediate alert + IP blocking

# Administrative Account Usage
- Query: user_name:"admin" OR user_name:"root" 
- Time: Outside business hours (6PM-8AM)
- Action: Security team notification

# New Process Execution
- Query: event_id:4688 AND process_name:NOT_IN_WHITELIST
- Scope: Critical servers only
- Action: Investigation workflow trigger
```

#### Warning Alerts
```yaml
# Unusual Login Locations
- Geographic IP analysis for user accounts
- First-time login locations
- VPN vs direct connections

# File System Changes
- Sensitive directory access (/etc, /var/log, C:\Windows\System32)
- Configuration file modifications
- Log file tampering attempts
```

### 🔐 **Access Control**
```bash
# Create role-based users
curl -k -u admin:${PASSWORD} -X POST \
  "https://localhost:9200/_plugins/_security/api/internalusers/analyst" \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "analyst_password",
    "roles": ["logs_reader", "dashboard_user"]
  }'
```

---

## 📈 Performance & Scaling

### Resource Requirements
| Deployment | RAM | CPU | Storage | Daily Log Volume |
|------------|-----|-----|---------|------------------|
| **Development** | 4GB | 2 cores | 20GB | <1GB |
| **Small Business** | 8GB | 4 cores | 100GB | 1-10GB |
| **Enterprise** | 32GB+ | 16+ cores | 1TB+ | 100GB+ |
| **Large Scale** | 128GB+ | 32+ cores | 10TB+ | 1TB+ |

### Scaling Strategies
```yaml
# Horizontal scaling - add nodes
services:
  opensearch-node3:
    image: opensearchproject/opensearch:latest
    environment:
      - node.name=opensearch-node3
      - cluster.initial_cluster_manager_nodes=opensearch-node1,opensearch-node2,opensearch-node3

# Load balancing
nginx:
  image: nginx:alpine
  ports:
    - "80:80"
    - "443:443"
  volumes:
    - ./nginx.conf:/etc/nginx/nginx.conf
```

### Performance Optimization
```bash
# Production tuning in .env
OPENSEARCH_JAVA_OPTS=-Xms8g -Xmx8g
LS_JAVA_OPTS=-Xmx4g -Xms4g

# Index lifecycle management
curl -X POST "localhost:9200/_plugins/_ism/policies/log_policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "states": [
        {
          "name": "hot",
          "actions": [],
          "transitions": [{
            "state_name": "warm",
            "conditions": {"min_index_age": "7d"}
          }]
        },
        {
          "name": "warm", 
          "actions": [{"warm": {}}],
          "transitions": [{
            "state_name": "delete",
            "conditions": {"min_index_age": "90d"}
          }]
        },
        {"name": "delete", "actions": [{"delete": {}}]}
      ]
    }
  }'
```

---

## 🤖 MCP Server Integration

### API Endpoints
```bash
# Health check
curl http://localhost:8000/health

# List all indices with metadata
curl -X POST http://localhost:8000/mcp/tools/list_indices \
  -H "Content-Type: application/json" \
  -d '{"pattern": "*", "include_system": false}'

# Execute SQL queries
curl -X POST http://localhost:8000/mcp/tools/execute_sql \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM \"logstash-logs-*\" WHERE syslog_severity <= 3 LIMIT 10"}'

# Search with complex filters
curl -X POST http://localhost:8000/mcp/tools/search_documents \
  -H "Content-Type: application/json" \
  -d '{
    "index": "logstash-logs-*",
    "query": {
      "bool": {
        "must": [
          {"range": {"@timestamp": {"gte": "now-1h"}}},
          {"match": {"syslog_program": "sshd"}}
        ]
      }
    },
    "size": 50
  }'
```

### Claude Desktop Integration
```json
{
  "mcpServers": {
    "opensearch-logs": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "http://YOUR_SERVER_IP:8000/mcp"
      ]
    }
  }
}
```

### AI Assistant Use Cases
- **🔍 Intelligent Log Analysis**: "Show me all failed login attempts from the last hour"
- **📊 Trend Analysis**: "What are the top 10 error sources this week?"
- **🚨 Security Investigations**: "Find suspicious activity patterns for user X"
- **📈 Performance Monitoring**: "Identify services with increasing error rates"

---

## 📊 Dashboard Examples

### Security Operations Center (SOC)
```bash
# Import pre-built dashboards
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -F file=@dashboards/soc-dashboard.ndjson
```

### Key Visualizations
- **🔥 Real-time Event Stream**: Live log feed with filtering
- **🌍 Geographic Attack Map**: Login attempts by location
- **📊 Security Event Timeline**: Historical attack patterns
- **⚠️ Alert Summary**: Current threats and their severity
- **💻 System Health Overview**: Infrastructure status across all monitored systems

---

## 🛡️ Security Features

### 🎯 **Built-in Detection Rules**

#### Critical Security Events
```yaml
# Brute Force Attacks
- Pattern: Multiple authentication failures
- Threshold: >5 failures in 5 minutes per source IP
- Response: Auto-block + SOC alert

# Privilege Escalation
- Pattern: sudo/su usage, admin group additions
- Scope: Non-service accounts
- Response: Immediate investigation trigger

# Suspicious Process Execution
- Pattern: PowerShell/cmd.exe with encoded commands
- Pattern: Unusual parent-child process relationships
- Response: Process analysis + containment

# Data Access Anomalies  
- Pattern: Large file transfers outside business hours
- Pattern: Access to sensitive directories
- Response: Data loss prevention workflow
```

#### Windows-Specific Detection
```yaml
# Event ID Monitoring
4624: Successful logon (track unusual locations/times)
4625: Failed logon (brute force detection)
4648: Explicit credential use (lateral movement)
4656: File/object access (data access monitoring)
4719: System audit policy changes (tampering detection)
4720: User account created (account management)

# PowerShell Security
4103: Module logging (malicious command detection)
4104: Script block logging (obfuscated script analysis)
4105: Script start (execution monitoring)
4106: Script stop (completion tracking)
```

### 🔐 **Authentication & Access Control**
```bash
# Create security roles
curl -k -u admin:${PASSWORD} -X PUT \
  "https://localhost:9200/_plugins/_security/api/roles/security_analyst" \
  -H 'Content-Type: application/json' \
  -d '{
    "cluster_permissions": ["cluster_composite_ops_ro"],
    "index_permissions": [{
      "index_patterns": ["logstash-logs-*", "security-events-*"],
      "allowed_actions": ["read", "search"]
    }]
  }'

# Create users with specific roles
curl -k -u admin:${PASSWORD} -X PUT \
  "https://localhost:9200/_plugins/_security/api/internalusers/analyst1" \
  -H 'Content-Type: application/json' \
  -d '{
    "password": "secure_password",
    "roles": ["security_analyst"],
    "attributes": {
      "department": "Security",
      "clearance_level": "L2"
    }
  }'
```

---

## 🔧 Advanced Configuration

### High Availability Setup
```yaml
# Add load balancer
nginx:
  image: nginx:alpine
  ports:
    - "80:80"
    - "443:443"
  volumes:
    - ./nginx/nginx.conf:/etc/nginx/nginx.conf
    - ./nginx/ssl:/etc/nginx/ssl
  depends_on:
    - opensearch-node1
    - opensearch-node2

# Cross-cluster replication
opensearch-remote:
  image: opensearchproject/opensearch:latest
  environment:
    - cluster.name=opensearch-backup
    - replication.enabled=true
```

### Custom Log Processing Pipelines
```ruby
# Enhanced logstash pipeline for Windows events
filter {
  if [agent][type] == "winlogbeat" {
    # Windows Event ID classification
    if [winlog][event_id] in [4624, 4634] {
      mutate { add_tag => ["authentication"] }
    }
    if [winlog][event_id] in [4625, 4648] {
      mutate { add_tag => ["failed_auth", "security_alert"] }
    }
    if [winlog][event_id] in [4656, 4658, 4660, 4663] {
      mutate { add_tag => ["file_access", "audit"] }
    }
    
    # Extract user and computer information
    grok {
      match => {
        "[winlog][event_data][SubjectUserName]" => "(?<user_name>[^$]+)"
      }
      tag_on_failure => ["_grok_user_failure"]
    }
    
    # GeoIP enrichment for external IPs
    if [winlog][event_data][IpAddress] and [winlog][event_data][IpAddress] !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ {
      geoip {
        source => "[winlog][event_data][IpAddress]"
        target => "geoip"
        database => "/usr/share/GeoIP/GeoLite2-City.mmdb"
      }
    }
  }
}

# Output to specialized indices
output {
  if "security_alert" in [tags] {
    opensearch {
      index => "security-events-%{+YYYY.MM.dd}"
      # ... connection details
    }
  } else if "authentication" in [tags] {
    opensearch {
      index => "auth-logs-%{+YYYY.MM.dd}"
      # ... connection details  
    }
  } else {
    opensearch {
      index => "logstash-logs-%{+YYYY.MM.dd}"
      # ... connection details
    }
  }
}
```

---

## 📊 Monitoring & Alerting

### Health Monitoring
```bash
# Service health checks
docker-compose exec opensearch-node1 curl -k \
  "https://localhost:9200/_cluster/health?pretty"

# Logstash pipeline monitoring  
curl "http://localhost:9600/_node/stats/pipelines?pretty"

# MCP server status
curl "http://localhost:8000/health"
```

### Performance Metrics
```bash
# Index statistics
curl -k -u admin:${PASSWORD} \
  "https://localhost:9200/_cat/indices/logstash-logs-*?v&s=store.size:desc"

# Search performance
curl -k -u admin:${PASSWORD} \
  "https://localhost:9200/_nodes/stats/indices/search?pretty"

# Memory usage
curl -k -u admin:${PASSWORD} \
  "https://localhost:9200/_cat/nodes?v&h=name,heap.percent,ram.percent,cpu"
```

---

## 🔧 Troubleshooting

### Common Issues

#### OpenSearch Won't Start
```bash
# Check logs
docker-compose logs opensearch-node1

# Common fixes
sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf

# Verify disk space
df -h
```

#### Logstash Processing Issues
```bash
# Check pipeline status
curl "http://localhost:9600/_node/stats/pipelines?pretty"

# Monitor processing rates
docker-compose logs logstash | grep -E "(ERROR|WARN)"

# Test configuration
docker-compose exec logstash logstash --config.test_and_exit
```

#### MCP Server Connection Problems
```bash
# Test MCP connectivity
curl http://localhost:8000/health

# Check OpenSearch connectivity from MCP
docker-compose exec mcp-server python -c "
from mcp_tools import OpenSearchClient
client = OpenSearchClient('https://opensearch-node1:9200', 'admin', '${PASSWORD}')
print(client.health_check())
"
```

### Log Analysis Commands
```bash
# Find parsing failures
curl -k -u admin:${PASSWORD} \
  "https://localhost:9200/logstash-logs-*/_search?q=tags:_grokparsefailure"

# Monitor ingestion rates
curl -k -u admin:${PASSWORD} \
  "https://localhost:9200/_cat/indices/logstash-logs-*?v&s=docs.count:desc"

# Check for duplicate events
curl -k -u admin:${PASSWORD} -X POST \
  "https://localhost:9200/logstash-logs-*/_search" \
  -d '{"aggs":{"duplicates":{"terms":{"field":"message.keyword","size":10}}}}'
```

---

## 🚀 Production Deployment

### Security Hardening
```yaml
# SSL/TLS Configuration
opensearch-node1:
  environment:
    - plugins.security.ssl.http.enabled=true
    - plugins.security.ssl.http.pemcert_filepath=certs/node1.pem
    - plugins.security.ssl.http.pemkey_filepath=certs/node1-key.pem
  volumes:
    - ./certs:/usr/share/opensearch/config/certs:ro

# Firewall rules (UFW example)
sudo ufw allow from TRUSTED_NETWORK to any port 9200
sudo ufw allow from TRUSTED_NETWORK to any port 5601
sudo ufw allow 514/tcp  # Syslog
sudo ufw allow 5044/tcp # Beats
```

### Backup & Recovery
```bash
# Snapshot configuration
curl -k -u admin:${PASSWORD} -X PUT \
  "https://localhost:9200/_snapshot/backup_repository" \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "fs",
    "settings": {
      "location": "/usr/share/opensearch/backups",
      "compress": true
    }
  }'

# Automated daily snapshots
curl -k -u admin:${PASSWORD} -X PUT \
  "https://localhost:9200/_plugins/_ism/policies/snapshot_policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
      "description": "Daily snapshots",
      "default_state": "snapshot",
      "states": [{
        "name": "snapshot",
        "actions": [{"snapshot": {"snapshot": "daily-{now/d}"}}],
        "transitions": [{"state_name": "snapshot", "conditions": {"cron": {"cron": {"expression": "0 2 * * *"}}}}]
      }]
    }
  }'
```

---

## 📚 Documentation & Resources

### 📖 Additional Documentation
- [🔧 Advanced Logstash Configuration](./docs/logstash-advanced.md)
- [🪟 Windows Event Collection Setup](./docs/windows-setup.md)
- [🐧 Linux Log Sources Configuration](./docs/linux-setup.md)
- [🛡️ Security Rules and Alerting](./docs/security-rules.md)
- [🚀 Production Deployment Guide](./docs/production.md)
- [🎯 API Reference](./docs/api-reference.md)

### 🔗 External Resources
- [OpenSearch Documentation](https://opensearch.org/docs/)
- [Logstash Configuration Reference](https://www.elastic.co/guide/en/logstash/current/configuration.html)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [SIGMA Rules](https://github.com/SigmaHQ/sigma)

### 🎓 Learning Resources
- [OpenSearch Query DSL](https://opensearch.org/docs/latest/query-dsl/)
- [Grok Pattern Testing](https://grokdebug.herokuapp.com/)
- [Regular Expression Testing](https://regex101.com/)

---

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting PRs.

### Development Setup
```bash
# Clone repository
git clone https://github.com/your-username/opensearch-centralized-logs.git
cd opensearch-centralized-logs

# Setup development environment
cp .env_example .env
docker-compose -f docker-compose.dev.yml up -d

# Run tests
make test-all

# Lint code
make lint

# Generate documentation
make docs
```

### 🐛 Issue Templates
- **Bug Report**: Use for functional issues
- **Feature Request**: Suggest new capabilities
- **Security Issue**: Report security vulnerabilities privately
- **Documentation**: Improve docs and examples

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🌟 Support & Community

- 📧 **Issues**: [GitHub Issues](https://github.com/your-username/opensearch-centralized-logs/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-username/opensearch-centralized-logs/discussions)  
- 📖 **Wiki**: [Project Wiki](https://github.com/your-username/opensearch-centralized-logs/wiki)
- 🆘 **Support**: [Community Forum](https://github.com/your-username/opensearch-centralized-logs/discussions/categories/q-a)

### 🏆 Contributors
Thanks to our amazing contributors! See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list.

---

## 🎯 Roadmap

### 📅 **Q1 2025**
- [ ] Enhanced Windows Event parsing
- [ ] Machine learning-based anomaly detection  
- [ ] Mobile device log integration
- [ ] Advanced compliance reporting

### 📅 **Q2 2025**
- [ ] Kubernetes log collection
- [ ] Cloud-native deployment options
- [ ] Advanced correlation engine
- [ ] Custom plugin marketplace

### 📅 **Q3 2025**
- [ ] Multi-tenant architecture
- [ ] Enterprise SSO integration
- [ ] Advanced threat hunting tools
- [ ] Automated incident response

---

<div align="center">

**⭐ Star this repository if you find it useful!**

**🔗 [View on GitHub](https://github.com/your-username/opensearch-centralized-logs) | 📖 [Documentation](./docs/) | 🚀 [Get Started](#-quick-start)**

*Built with ❤️ for the cybersecurity and DevOps community*

</div>