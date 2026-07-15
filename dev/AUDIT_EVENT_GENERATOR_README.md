# Audit Event Generator Utility

## Overview

The `AuditEventGenerator` is a standalone Java utility that generates thousands of audit events in Open Liberty's audit log JSON format. This is useful for testing audit log processing, performance testing, and filling audit logs for development purposes.

## Compilation

```bash
cd dev
javac AuditEventGenerator.java
```

## Usage

### Basic Syntax

```bash
java AuditEventGenerator --output <file> [--count <number> | --duration <seconds>]
```

### Options

- `--output, -o <file>` - Output file path (required)
- `--count, -c <number>` - Generate specified number of events (default: 1000)
- `--duration, -d <seconds>` - Generate events for specified duration in seconds
- `--rate, -r <events/sec>` - Events per second when using duration mode (default: 10)
- `--help, -h` - Display help message

### Examples

#### Generate 5000 events
```bash
java AuditEventGenerator --output audit.log --count 5000
```

#### Generate events for 10 minutes (600 seconds) at 20 events/second
```bash
java AuditEventGenerator --output audit.log --duration 600 --rate 20
```

#### Generate events for 5 minutes at default rate (10 events/second)
```bash
java AuditEventGenerator --output audit.log --duration 300
```

## How to Use with Open Liberty Server

There are two main approaches to use the generated audit events with your Open Liberty server:

### Approach 1: Generate Directly to Server's Audit Log (Recommended)

Generate the audit events directly to your server's audit log location:

```bash
# Generate 5000 events to the server's audit log
java AuditEventGenerator --output build.image/wlp/usr/servers/defaultServer/logs/audit.log --count 5000
```

**Important Notes:**
- The server should be **stopped** when you do this, or you may need to append to an existing file
- If the server is running, it may overwrite or conflict with your generated events
- This approach fills the audit log that the server will read when it starts

### Approach 2: Generate to a Separate File and Configure Server

1. **Generate the audit events to a file:**
   ```bash
   java AuditEventGenerator --output /tmp/generated-audit.log --count 5000
   ```

2. **Copy or move the file to your server's audit log location:**
   ```bash
   cp /tmp/generated-audit.log build.image/wlp/usr/servers/defaultServer/logs/audit.log
   ```

3. **Start your server** - The server will see the pre-filled audit log

### Approach 3: Continuous Generation While Server is Running

If you want to continuously generate events while the server is running:

1. **Configure your server to use a specific audit log file** in `server.xml`:
   ```xml
   <auditFileHandler maxFiles="5" maxFileSize="20" compact="false">
       <logDirectory>${server.output.dir}/logs</logDirectory>
   </auditFileHandler>
   ```

2. **Generate events to a temporary file:**
   ```bash
   java AuditEventGenerator --output /tmp/new-events.log --count 1000
   ```

3. **Append to the server's audit log:**
   ```bash
   cat /tmp/new-events.log >> build.image/wlp/usr/servers/defaultServer/logs/audit.log
   ```

**Note:** This approach may cause issues if the server is actively writing to the file. It's safer to stop the server first.

## Server Configuration

To ensure your Open Liberty server is configured for audit logging, add this to your `server.xml`:

```xml
<featureManager>
    <feature>audit-1.0</feature>
</featureManager>

<audit>
    <auditFileHandler maxFiles="10" maxFileSize="100" compact="false"/>
</audit>
```

## Generated Event Types

The utility generates the following types of audit events:

- `SECURITY_AUTHN` - Authentication events
- `SECURITY_AUTHZ` - Authorization events
- `SECURITY_AUDIT_MGMT` - Audit management events
- `JMX_MBEAN` - JMX MBean events
- `JMX_MBEAN_ATTRIBUTES` - JMX MBean attribute events

Each event includes:
- Unique sequence number
- Timestamp
- Observer information (server details)
- Outcome (success, failure, challenge, redirect)
- Target information (varies by event type)

## Example Workflow

Here's a complete workflow to fill your server's audit log:

```bash
# 1. Stop your server (if running)
./build.image/wlp/bin/server stop defaultServer

# 2. Generate 5000 audit events
cd dev
java AuditEventGenerator --output ../build.image/wlp/usr/servers/defaultServer/logs/audit.log --count 5000

# 3. Start your server
cd ..
./build.image/wlp/bin/server start defaultServer

# 4. Your server now has a pre-filled audit log with 5000 events!
```

## Performance

The utility can generate events very quickly:
- **Count mode**: Typically 10,000-30,000 events/second
- **Duration mode**: Rate-limited to your specified events/second

Example output:
```
Generation complete!
Total events: 5000
Duration: 0.16 seconds
Average rate: 30864.20 events/second
Output file: audit-generated-5000.log
```

## Troubleshooting

### Server doesn't see the events

- Ensure the file is in the correct location: `<server-dir>/logs/audit.log`
- Check that the server's audit feature is enabled in `server.xml`
- Verify the JSON format is correct by comparing with a real audit log

### File permission issues

- Ensure the file has appropriate read/write permissions
- The server process needs to be able to read the audit log file

### Events are overwritten

- Stop the server before generating events to its audit log
- Or generate to a different file and copy it when the server is stopped

## Additional Notes

- The utility generates realistic-looking audit events with varied usernames, resources, and outcomes
- Sequence numbers start at 0 and increment for each event
- Timestamps are generated at the time of event creation
- The server path in events is automatically detected from your hostname

## Support

For issues or questions about this utility, refer to the Open Liberty documentation on audit logging:
https://openliberty.io/docs/latest/audit-logs.html