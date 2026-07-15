# How to Run AuditEventTrigger

This guide explains how to run the AuditEventTrigger utility to generate thousands of audit events in Open Liberty.

## Prerequisites

### 1. Java Runtime
- Java 17 or Java 21 SDK installed
- `JAVA_HOME` environment variable set

### 2. Open Liberty Server Running
Your Open Liberty server must be:
- **Running** on the target URL (default: https://localhost:9443)
- **Configured** with the `audit-1.0` feature
- **Deployed** with the `auditTest` application
- **Configured** with user credentials (default: admin/adminpwd)

### 3. Server Configuration
Your `server.xml` should include:

```xml
<server>
    <!-- Enable audit feature -->
    <featureManager>
        <feature>audit-1.0</feature>
        <feature>servlet-4.0</feature>
        <!-- other features -->
    </featureManager>
    
    <!-- Configure audit handler -->
    <auditFileHandler maxFiles="100" maxFileSize="200" compact="false">
        <events name="AuditEvent_security_authn" eventName="SECURITY_AUTHN" outcome="success"/>
        <events name="AuditEvent_security_authn_fail" eventName="SECURITY_AUTHN" outcome="failure"/>
        <events name="AuditEvent_security_authz" eventName="SECURITY_AUTHZ" outcome="success"/>
        <events name="AuditEvent_security_authz_fail" eventName="SECURITY_AUTHZ" outcome="denied"/>
    </auditFileHandler>
    
    <!-- User registry -->
    <basicRegistry>
        <user name="admin" password="adminpwd"/>
    </basicRegistry>
    
    <!-- SSL configuration -->
    <ssl id="defaultSSLConfig" keyStoreRef="defaultKeyStore" trustStoreRef="defaultTrustStore"/>
</server>
```

## Quick Start

### Step 1: Navigate to the dev directory
```bash
cd /Users/niyathar/libertyGit/open-liberty/dev
```

### Step 2: Compile the utility (if not already compiled)
```bash
javac AuditEventTrigger.java
```

### Step 3: Run with default settings
```bash
java AuditEventTrigger --url https://localhost:9443
```

This will generate **1000 audit events** at **10 events/second** to **https://localhost:9443**.

## Usage Options

### Option 1: Generate Specific Number of Events
Generate exactly 5000 audit events:
```bash
java AuditEventTrigger --url https://localhost:9443 --count 5000
```

Generate 10,000 events:
```bash
java AuditEventTrigger --url https://localhost:9443 --count 10000
```

### Option 2: Run for Specific Duration
Run for 10 minutes (600 seconds):
```bash
java AuditEventTrigger --url https://localhost:9443 --duration 600
```

Run for 1 hour (3600 seconds):
```bash
java AuditEventTrigger --url https://localhost:9443 --duration 3600
```

### Option 3: Control Event Generation Rate
Generate 5000 events at 20 events per second:
```bash
java AuditEventTrigger --url https://localhost:9443 --count 5000 --rate 20
```

Generate events for 600 seconds at 50 events per second:
```bash
java AuditEventTrigger --url https://localhost:9443 --duration 600 --rate 50
```

### Option 4: Custom Server URL
Target a different server:
```bash
java AuditEventTrigger --url https://myserver.example.com:9443 --count 5000
```

### Option 5: Custom Credentials
Use different username/password:
```bash
java AuditEventTrigger --url https://localhost:9443 --count 5000 --username testuser --password testpass
```

### Option 6: Combine Multiple Options
```bash
java AuditEventTrigger --url https://localhost:9443 --count 10000 --rate 25
```

## Command-Line Arguments

| Argument | Description | Default | Example |
|----------|-------------|---------|---------|
| `--url` | Server base URL | https://localhost:9443 | `--url https://myserver:9443` |
| `--count` | Number of events to generate | 1000 | `--count 5000` |
| `--duration` | Run for N seconds | (not set) | `--duration 600` |
| `--rate` | Events per second | 10 | `--rate 20` |

**Note:** You can specify either `--count` OR `--duration`, but not both.

## What Happens When You Run It

### 1. Connection Established
```
Starting audit event generation...
Target URL: https://localhost:9443
```

### 2. Events Generated
The utility makes HTTPS requests to 5 endpoints:
- `/auditTest/` - Main application
- `/auditTest/secure` - Secure endpoint
- `/auditTest/admin` - Admin endpoint
- `/auditTest/test` - Test endpoint
- `/auditTest/api` - API endpoint

### 3. Authentication Mix
Each request uses one of three strategies:
- **33% successful**: admin/adminpwd (correct credentials)
- **33% failed**: admin/wrongpassword (wrong password)
- **33% denied**: no authentication (unauthenticated)

### 4. Progress Updates
```
Generated 100 events (10.0 events/sec)
Generated 200 events (10.0 events/sec)
Generated 300 events (10.0 events/sec)
...
```

### 5. Completion Summary
```
Audit event generation complete!
Total events generated: 5000
Total time: 500.2 seconds
Average rate: 10.0 events/second
```

## Verifying Audit Events

### Check the audit log
```bash
# View the audit log
cat build.image/wlp/usr/servers/defaultServer/logs/audit.log

# Count audit events
grep -c "SECURITY_AUTHN" build.image/wlp/usr/servers/defaultServer/logs/audit.log
```

### Expected Audit Events
For 5000 requests, you should see approximately:
- **1667 SECURITY_AUTHN success** (successful authentications)
- **1667 SECURITY_AUTHN failure** (failed authentications)
- **1667 SECURITY_AUTHZ denied** (authorization denials)
- Plus additional SECURITY_AUTHZ success events for authorized requests

## Common Scenarios

### Scenario 1: Fill Audit Log Quickly
Generate 10,000 events as fast as possible (100 events/sec):
```bash
java AuditEventTrigger --count 10000 --rate 100
```

### Scenario 2: Continuous Load Testing
Run for 1 hour with moderate load (20 events/sec):
```bash
java AuditEventTrigger --duration 3600 --rate 20
```

### Scenario 3: Stress Test
Generate 50,000 events at maximum rate:
```bash
java AuditEventTrigger --count 50000 --rate 200
```

### Scenario 4: Overnight Run
Run for 8 hours (28,800 seconds) at low rate:
```bash
java AuditEventTrigger --duration 28800 --rate 5
```

## Troubleshooting

### Problem: Connection Refused
```
Error: Connection refused
```
**Solution:** Ensure your Open Liberty server is running:
```bash
cd build.image/wlp/bin
./server start defaultServer
```

### Problem: SSL Certificate Error
```
Error: PKIX path building failed
```
**Solution:** The utility already disables SSL verification for testing. If you still see this, check your Java security settings.

### Problem: 404 Not Found
```
Error: HTTP 404 - /auditTest/ not found
```
**Solution:** Deploy the auditTest application to your server.

### Problem: 401 Unauthorized (all requests)
```
Error: All requests returning 401
```
**Solution:** Check that the admin user exists in your server.xml:
```xml
<basicRegistry>
    <user name="admin" password="adminpwd"/>
</basicRegistry>
```

### Problem: No Audit Events Generated
**Solution:** Verify audit feature is enabled in server.xml:
```xml
<featureManager>
    <feature>audit-1.0</feature>
</featureManager>
```

## Performance Considerations

### Rate Limits
- **Low rate (1-10 events/sec)**: Good for long-running tests
- **Medium rate (10-50 events/sec)**: Typical production load
- **High rate (50-100 events/sec)**: Stress testing
- **Very high rate (100+ events/sec)**: May overwhelm server

### Server Impact
- Each request triggers 1-2 audit events
- High rates may impact server performance
- Monitor server CPU and memory usage
- Check audit log file size growth

### Recommended Settings
For filling audit log without overwhelming server:
```bash
java AuditEventTrigger --count 5000 --rate 20
```

This generates 5000 events in ~4 minutes at a sustainable rate.

## Advanced Usage

### Run in Background
```bash
nohup java AuditEventTrigger --duration 3600 --rate 10 > audit-trigger.log 2>&1 &
```

### Multiple Concurrent Instances
Run multiple instances to increase load:
```bash
# Terminal 1
java AuditEventTrigger --count 5000 --rate 20 &

# Terminal 2
java AuditEventTrigger --count 5000 --rate 20 &

# Terminal 3
java AuditEventTrigger --count 5000 --rate 20 &
```

### Scheduled Runs
Use cron to run periodically:
```bash
# Run every hour
0 * * * * cd /Users/niyathar/libertyGit/open-liberty/dev && java AuditEventTrigger --count 1000
```

## Summary

The AuditEventTrigger utility is a powerful tool for:
- ✅ Generating thousands of audit events quickly
- ✅ Testing audit logging configuration
- ✅ Filling audit logs for testing
- ✅ Load testing audit infrastructure
- ✅ Validating audit event handling

**Most Common Command:**
```bash
java AuditEventTrigger --count 5000 --rate 20
```

This generates 5000 audit events in approximately 4 minutes, filling your audit log with a realistic mix of authentication successes, failures, and authorization denials.