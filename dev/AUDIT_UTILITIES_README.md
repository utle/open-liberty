# Open Liberty Audit Event Generation Utilities

This directory contains two utilities for generating audit events in Open Liberty for testing purposes.

## Overview

### 1. AuditEventTrigger (Recommended)
**Makes real HTTP requests to a running server to generate actual audit events.**

- ✅ Generates real audit events through the server's audit system
- ✅ Server must be running
- ✅ Events appear in the server's audit log automatically
- ✅ Simulates realistic user activity

### 2. AuditEventGenerator
**Writes audit events directly to a file in JSON format.**

- ✅ Fast generation (10,000+ events/second)
- ✅ Server must be stopped
- ✅ Useful for pre-filling audit logs
- ✅ Good for testing audit log readers

---

## AuditEventTrigger - HTTP Request Based (Recommended)

### Description
This utility makes HTTP requests to your running Open Liberty server, triggering real audit events through the server's security and audit subsystems. This is the most realistic way to generate audit events.

### Prerequisites
- Open Liberty server must be running
- Audit feature must be enabled in server.xml
- Server must be accessible via HTTP/HTTPS

### Compilation
```bash
cd dev
javac AuditEventTrigger.java
```

### Usage

#### Basic Syntax
```bash
java AuditEventTrigger --url <base-url> [OPTIONS]
```

#### Options
- `--url, -u <base-url>` - Base URL of the server (required)
  - Example: `http://localhost:9080` or `https://localhost:9443`
- `--count, -c <number>` - Generate specified number of events (default: 1000)
- `--duration, -d <seconds>` - Generate events for specified duration in seconds
- `--rate, -r <events/sec>` - Events per second (default: 10)
- `--username <user>` - Username for authentication (default: testuser)
- `--password <pass>` - Password for authentication (default: testpass)
- `--help, -h` - Display help message

### Examples

#### Generate 5000 audit events
```bash
java AuditEventTrigger --url http://localhost:9080 --count 5000
```

#### Generate events for 10 minutes at 20 events/second
```bash
java AuditEventTrigger --url http://localhost:9080 --duration 600 --rate 20
```

#### Generate events with custom credentials
```bash
java AuditEventTrigger --url https://localhost:9443 --count 1000 \
     --username admin --password adminpass
```

### How It Works

The utility:
1. Makes HTTP requests to various endpoints on your server
2. Uses different HTTP methods (GET, POST, PUT, DELETE)
3. Randomly includes authentication (both correct and incorrect passwords)
4. Generates a mix of successful and failed requests
5. Each request triggers audit events in your server's audit log

### Server Configuration

Ensure your `server.xml` has audit logging enabled:

```xml
<featureManager>
    <feature>audit-1.0</feature>
</featureManager>

<audit>
    <auditFileHandler maxFiles="10" maxFileSize="100" compact="false"/>
</audit>
```

### Expected Output

```
Starting audit event generation via HTTP requests...
Target server: http://localhost:9080
Count: 5000 events

Generating audit events by making HTTP requests...

Generated 5000 events (Success: 4823, Failed: 177)...

Generation complete!
Total requests: 5000
Successful: 4823
Failed: 177
Duration: 8.45 seconds
Average rate: 591.72 events/second

Check your server's audit log for the generated events.
```

### Viewing Generated Events

Check your server's audit log:
```bash
tail -f build.image/wlp/usr/servers/defaultServer/logs/audit.log
```

---

## AuditEventGenerator - File Based

### Description
This utility writes audit events directly to a file in Open Liberty's JSON audit log format. Useful for pre-filling audit logs or testing audit log processing tools.

### Prerequisites
- Server should be stopped (to avoid file conflicts)
- Java 8 or higher

### Compilation
```bash
cd dev
javac AuditEventGenerator.java
```

### Usage

#### Basic Syntax
```bash
java AuditEventGenerator --output <file> [OPTIONS]
```

#### Options
- `--output, -o <file>` - Output file path (required)
- `--count, -c <number>` - Generate specified number of events (default: 1000)
- `--duration, -d <seconds>` - Generate events for specified duration
- `--rate, -r <events/sec>` - Events per second for duration mode (default: 10)
- `--help, -h` - Display help message

### Examples

#### Generate 5000 events to a file
```bash
java AuditEventGenerator --output audit.log --count 5000
```

#### Generate directly to server's audit log
```bash
java AuditEventGenerator --output build.image/wlp/usr/servers/defaultServer/logs/audit.log --count 5000
```

#### Generate for 10 minutes at 20 events/second
```bash
java AuditEventGenerator --output audit.log --duration 600 --rate 20
```

### Workflow for Pre-filling Server Audit Log

```bash
# 1. Stop your server
./build.image/wlp/bin/server stop defaultServer

# 2. Generate events to the server's audit log
cd dev
java AuditEventGenerator --output ../build.image/wlp/usr/servers/defaultServer/logs/audit.log --count 5000

# 3. Start your server
cd ..
./build.image/wlp/bin/server start defaultServer

# Your server now has a pre-filled audit log!
```

---

## Convenience Script

A shell script is provided for easy usage:

```bash
./generate-audit-events.sh --help
```

### Script Examples

```bash
# Generate 5000 events (stops server first)
./generate-audit-events.sh --count 5000 --stop-server

# Generate for 10 minutes
./generate-audit-events.sh --duration 600 --rate 20
```

---

## Comparison

| Feature | AuditEventTrigger | AuditEventGenerator |
|---------|-------------------|---------------------|
| Server State | Must be running | Must be stopped |
| Event Generation | Real HTTP requests | Direct file write |
| Speed | ~100-1000/sec | ~10,000-30,000/sec |
| Realism | High (actual events) | Medium (simulated) |
| Use Case | Testing live system | Pre-filling logs |
| Audit Event Types | AUTHN, AUTHZ | AUTHN, AUTHZ, JMX, MGMT |

---

## Event Types Generated

### AuditEventTrigger
- `SECURITY_AUTHN` - Authentication events (successful and failed)
- `SECURITY_AUTHZ` - Authorization events
- Various HTTP response codes (200, 401, 403, 404, etc.)

### AuditEventGenerator
- `SECURITY_AUTHN` - Authentication events
- `SECURITY_AUTHZ` - Authorization events
- `SECURITY_AUDIT_MGMT` - Audit management events
- `JMX_MBEAN` - JMX MBean events
- `JMX_MBEAN_ATTRIBUTES` - JMX MBean attribute events

---

## Troubleshooting

### AuditEventTrigger Issues

**Problem:** Connection refused
- **Solution:** Ensure the server is running and the URL is correct

**Problem:** No audit events generated
- **Solution:** Check that audit feature is enabled in server.xml

**Problem:** SSL/TLS errors with HTTPS
- **Solution:** Use HTTP for testing, or configure proper SSL certificates

### AuditEventGenerator Issues

**Problem:** File permission denied
- **Solution:** Ensure you have write permissions to the output directory

**Problem:** Events overwritten by server
- **Solution:** Stop the server before generating events to its audit log

**Problem:** Server doesn't see the events
- **Solution:** Verify the file is in the correct location and has proper permissions

---

## Performance Tips

### For High-Volume Testing (AuditEventTrigger)
- Use `--rate` to control load on the server
- Monitor server CPU and memory usage
- Consider running multiple instances with different endpoints

### For Fast Generation (AuditEventGenerator)
- Use count mode for maximum speed
- Write to a fast disk (SSD)
- Generate to a temporary file, then copy to server location

---

## Additional Resources

- [Open Liberty Audit Documentation](https://openliberty.io/docs/latest/audit-logs.html)
- [Security Audit Feature](https://openliberty.io/docs/latest/reference/feature/audit-1.0.html)

---

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the Open Liberty audit documentation
3. Examine the generated audit log format

## License

Copyright (c) 2026 IBM Corporation and others.
Licensed under the Eclipse Public License 2.0.