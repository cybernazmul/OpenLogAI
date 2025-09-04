# RSyslog to Logstash Integration Setup

## Status: ✅ WORKING

Your Logstash is now successfully configured to receive rsyslog data and forward it to OpenSearch.

## Setup Instructions

### 1. Configure rsyslog on your system

Add this line to `/etc/rsyslog.conf` or create `/etc/rsyslog.d/50-logstash.conf`:

```bash
# Forward all logs to Logstash via TCP
*.* @@localhost:514

# Or forward specific facilities:
# mail.* @@localhost:514
# kern.* @@localhost:514
# auth.* @@localhost:514
```

### 2. Restart rsyslog service

```bash
sudo systemctl restart rsyslog
```

### 3. Test the integration

Generate test log entries:
```bash
logger "Test message from rsyslog"
```

Or use netcat for testing:
```bash
echo "<14>$(date '+%b %d %H:%M:%S') $(hostname) test: Test message" | nc localhost 514
```

## Verification

1. **Check Logstash logs**: `docker logs logstash --tail 20`
2. **Query OpenSearch**: 
   ```bash
   curl -k -u admin:IWV@nazmul2110 "https://localhost:9200/logstash-logs-*/_search?pretty"
   ```
3. **View in OpenSearch Dashboards**: http://localhost:5601

## Current Configuration

- **Logstash TCP Port**: 514 (receives rsyslog data)
- **Logstash UDP Port**: 514 (receives rsyslog data)
- **Logstash API**: http://localhost:9601
- **OpenSearch Index Pattern**: `logstash-logs-YYYY.MM.dd`
- **OpenSearch Dashboards**: http://localhost:5601

## Test Results ✅

Successfully tested with 2 sample messages:
- Both messages were received by Logstash
- Both messages were parsed and processed
- Both messages were indexed in OpenSearch (`logstash-logs-2025.09.03`)
- Data is queryable via OpenSearch API and Dashboards