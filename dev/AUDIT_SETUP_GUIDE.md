# Complete Setup Guide for Audit Event Generation

## Your Current Server Configuration

Your server at `/Users/niyathar/libertyGit/open-liberty/dev/build.image/wlp/usr/servers/defaultServer` is already configured with:

✅ `audit-1.0` feature enabled
✅ `appSecurity-3.0` feature enabled  
✅ `auditFileHandler` configured
✅ HTTP endpoints on ports 9080 (HTTP) and 9443 (HTTPS)

## Required: Add User Registry

To generate authentication audit events, you need to add a user registry to your `server.xml`. Here's what to add:

### Option 1: Basic User Registry (Recommended for Testing)

Add this to your `server.xml` (after the `</featureManager>` section):

```xml
<!-- Basic User Registry for Testing -->
<basicRegistry id="basic" realm="BasicRealm">
    <user name="testuser" password="testpass" />
    <user name="admin" password="adminpass" />
    <user name="user1" password="password1" />
    <user name="user2" password="password2" />
</basicRegistry>

<!-- Application Security -->
<application id="defaultApp" name="defaultApp" type="war" location="defaultApp.war">
    <application-bnd>
        <security-role name="users">
            <user name="testuser" />
            <user name="user1" />
            <user name="user2" />
        </security-role>
        <security-role name="admin">
            <user name="admin" />
        </security-role>
    </application-bnd>
</application>
```

### Option 2: Quick Registry (Even Simpler)

Or use this minimal configuration:

```xml
<quickStartSecurity userName="admin" userPassword="adminpass" />
```

## Complete Working server.xml Example

Here's a complete working configuration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<server description="Audit Testing Server">

    <!-- Enable features -->
    <featureManager>
        <feature>jsp-2.3</feature>
        <feature>audit-1.0</feature>
        <feature>appSecurity-3.0</feature>
        <feature>servlet-4.0</feature>
    </featureManager>

    <!-- HTTP Endpoints -->
    <httpEndpoint id="defaultHttpEndpoint"
                  httpPort="9080"
                  httpsPort="9443"
                  host="*" />

    <!-- Basic User Registry -->
    <basicRegistry id="basic" realm="BasicRealm">
        <user name="testuser" password="testpass" />
        <user name="admin" password="adminpass" />
        <user name="user1" password="password1" />
        <user name="user2" password="password2" />
    </basicRegistry>

    <!-- Audit Configuration -->
    <auditFileHandler maxFiles="100" maxFileSize="100" compact="false">
        <events name="SECURITY_AUTHN" eventName="SECURITY_AUTHN" outcome="success"/>
        <events name="SECURITY_AUTHN" eventName="SECURITY_AUTHN" outcome="failure"/>
        <events name="SECURITY_AUTHZ" eventName="SECURITY_AUTHZ" outcome="success"/>
        <events name="SECURITY_AUTHZ" eventName="SECURITY_AUTHZ" outcome="denied"/>
    </auditFileHandler>

    <!-- SSL Configuration -->
    <keyStore id="defaultKeyStore" password="Liberty" />
    <ssl id="defaultSSLConfig" trustDefaultCerts="true" />

    <!-- LTPA -->
    <ltpa keysPassword="{xor}CDo9Hgw=" />

    <!-- Automatically expand WAR files -->
    <applicationManager autoExpand="true"/>

</server>
```

## Step-by-Step Setup

### 1. Update Your server.xml

Add the basic user registry to your existing `server.xml`:

```bash
# Edit your server.xml
vi dev/build.image/wlp/usr/servers/defaultServer/server.xml
```

Add the `<basicRegistry>` section shown above.

### 2. Start Your Server

```bash
cd dev/build.image/wlp/bin
./server start defaultServer
```

Verify it's running:
```bash
./server status defaultServer
```

### 3. Compile the Audit Event Trigger

```bash
cd /Users/niyathar/libertyGit/open-liberty/dev
javac AuditEventTrigger.java
```

### 4. Generate Audit Events

#### Generate 5000 events:
```bash
java AuditEventTrigger --url http://localhost:9080 --count 5000
```

#### Generate for 10 minutes (600 seconds) at 20 events/second:
```bash
java AuditEventTrigger --url http://localhost:9080 --duration 600 --rate 20
```

#### With custom credentials:
```bash
java AuditEventTrigger --url http://localhost:9080 --count 1000 \
     --username admin --password adminpass
```

### 5. View the Generated Audit Events

```bash
# View the audit log
tail -f dev/build.image/wlp/usr/servers/defaultServer/logs/audit.log

# Or count the events
grep -c "eventName" dev/build.image/wlp/usr/servers/defaultServer/logs/audit.log
```

## What the Utility Does

The `AuditEventTrigger` utility will:

1. **Make HTTP requests** to your server at `http://localhost:9080`
2. **Try different endpoints**: `/`, `/test`, `/api/data`, `/admin`, `/secure`, etc.
3. **Use various HTTP methods**: GET, POST, PUT, DELETE
4. **Mix authentication**:
   - Some requests with correct credentials (generates SUCCESS events)
   - Some requests with wrong passwords (generates FAILURE events)
   - Some requests without credentials (generates CHALLENGE events)
5. **Generate real audit events** through your server's audit system

## Expected Audit Events

You'll see events like:

```json
{
   "eventName": "SECURITY_AUTHN",
   "eventSequenceNumber": "123",
   "eventTime": "2026-07-14T10:58:00.000-0400",
   "observer": {
      "id": "websphere: mac:/Users/niyathar/libertyGit/open-liberty/dev/build.image/wlp/usr/:defaultServer",
      "name": "SecurityService",
      "typeURI": "service/server"
   },
   "outcome": "success",
   "target": {
      "name": "/test",
      "method": "GET",
      "credential.token": "testuser",
      "credential.type": "BASIC",
      "realm": "BasicRealm"
   }
}
```

## Troubleshooting

### Server won't start
```bash
# Check server logs
cat dev/build.image/wlp/usr/servers/defaultServer/logs/messages.log
```

### No audit events generated
1. Verify audit feature is enabled: `grep audit server.xml`
2. Check server is running: `./server status defaultServer`
3. Verify URL is correct: `curl http://localhost:9080`

### Connection refused
```bash
# Check if server is listening
netstat -an | grep 9080

# Or use lsof
lsof -i :9080
```

### Authentication not working
- Ensure `basicRegistry` is configured in server.xml
- Verify usernames and passwords match
- Check server logs for authentication errors

## Quick Test

Test your setup manually first:

```bash
# Test without authentication (should get 401)
curl -v http://localhost:9080/

# Test with correct credentials (should get 200 or 404)
curl -v -u testuser:testpass http://localhost:9080/

# Test with wrong credentials (should get 401)
curl -v -u testuser:wrongpass http://localhost:9080/
```

Each of these curl commands will generate audit events in your audit log!

## Performance Expectations

- **Low rate** (10 events/sec): Minimal server load, good for long-running tests
- **Medium rate** (50 events/sec): Moderate load, good for realistic testing
- **High rate** (100+ events/sec): Heavy load, tests server capacity

Monitor your server:
```bash
# Watch server CPU/memory
top -pid $(pgrep -f defaultServer)

# Watch audit log grow
watch -n 1 'wc -l dev/build.image/wlp/usr/servers/defaultServer/logs/audit.log'
```

## Summary

Your server is almost ready! Just add the user registry configuration, restart the server, and you can start generating thousands of audit events with the utility.

The key advantage of `AuditEventTrigger` over the file-based generator is that it generates **real audit events** through your server's actual security and audit subsystems, exactly like your curl test commands but automated and at scale.