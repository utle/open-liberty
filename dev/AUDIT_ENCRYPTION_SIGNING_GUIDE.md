# Open Liberty Audit Event Encryption and Signing Guide

This guide explains how to generate encrypted and signed audit events in Open Liberty using the advanced audit event generator utility.

## Overview

Open Liberty supports three modes of audit event generation:

1. **Plain Mode**: Standard audit events without encryption or signing
2. **Encrypted Mode**: Audit events encrypted with AES-256
3. **Signed Mode**: Audit events signed with digital signatures
4. **Both Mode**: Audit events that are both encrypted and signed

## Prerequisites

### 1. Keystores

You need two keystores for encryption and signing:

- **Encryption Keystore**: `resources/security/AuditEncryptionKeyStore.p12`
  - Contains the encryption key with alias `auditencryptionkey`
  - Password: `Liberty`

- **Signing Keystore**: `resources/security/AuditSigningKeyStore.p12`
  - Contains the signing key with alias `auditsigningkey`
  - Password: `Liberty`

### 2. Server Configuration

The `server.xml` file has been configured with:

```xml
<!-- Keystores -->
<keyStore
    id="auditEncKeyStore"
    password="Liberty"
    location="${server.config.dir}/resources/security/AuditEncryptionKeyStore.p12"
    type="PKCS12" />

<keyStore
    id="auditSignKeyStore"
    password="Liberty"
    location="${server.config.dir}/resources/security/AuditSigningKeyStore.p12"
    type="PKCS12" />

<!-- Plain audit handler (default) -->
<auditFileHandler maxFiles="100" maxFileSize="100" compact="false">
    <events name="SECURITY_AUTHN" eventName="SECURITY_AUTHN" outcome="success"/>
    <events name="SECURITY_AUTHN" eventName="SECURITY_AUTHN" outcome="failure"/>
    <events name="SECURITY_AUTHZ" eventName="SECURITY_AUTHZ" outcome="success"/>
    <events name="SECURITY_AUTHZ" eventName="SECURITY_AUTHZ" outcome="denied"/>
</auditFileHandler>

<!-- Encrypted and Signed audit handler (uncomment to enable) -->
<!-- 
<auditFileHandler 
    maxFiles="100" 
    maxFileSize="100" 
    compact="false"
    encrypt="true"
    encryptAlias="auditencryptionkey"
    encryptKeyStoreRef="auditEncKeyStore"
    sign="true"
    signingAlias="auditsigningkey"
    signingKeyStoreRef="auditSignKeyStore">
    <events name="SECURITY_AUTHN" eventName="SECURITY_AUTHN" outcome="success"/>
    <events name="SECURITY_AUTHN" eventName="SECURITY_AUTHN" outcome="failure"/>
    <events name="SECURITY_AUTHZ" eventName="SECURITY_AUTHZ" outcome="success"/>
    <events name="SECURITY_AUTHZ" eventName="SECURITY_AUTHZ" outcome="denied"/>
</auditFileHandler>
-->
```

## Using the Advanced Audit Event Generator

### Basic Usage

The `generate-audit-events-advanced.sh` script automatically configures the server and generates audit events in the specified mode.

```bash
# Generate 5000 plain audit events
./generate-audit-events-advanced.sh --mode plain --count 5000

# Generate encrypted and signed events for 10 minutes
./generate-audit-events-advanced.sh --mode both --duration 600

# Generate events at 50 events/second
./generate-audit-events-advanced.sh --mode both --count 10000 --rate 50
```

### Command-Line Options

```
-m, --mode MODE         Audit mode: plain, encrypted, signed, or both (default: plain)
-c, --count COUNT      Number of audit events to generate (default: 1000)
-d, --duration SECONDS Duration in seconds to generate events (overrides count)
-r, --rate RATE        Events per second (default: 20)
-u, --url URL          Server URL (default: http://localhost:9080)
--no-restart           Don't restart the server (use if already configured)
--compile              Force recompile of AuditEventTrigger.java
-h, --help             Display help message
```

## Manual Configuration

If you prefer to manually configure the server:

### 1. Enable Encrypted and Signed Audit Events

Edit `server.xml`:

1. Comment out the plain `<auditFileHandler>` section
2. Uncomment the encrypted and signed `<auditFileHandler>` section

### 2. Restart the Server

```bash
cd build.image/wlp/bin
./server stop defaultServer
./server start defaultServer
```

### 3. Generate Audit Events

```bash
cd dev
java AuditEventTrigger --count 5000 --rate 20
```

## Verifying Encrypted/Signed Audit Events

### 1. Check the Audit Log

Encrypted and signed audit events are stored in the same location as plain events:

```bash
cat build.image/wlp/usr/servers/defaultServer/logs/audit.log
```

However, the content will be encrypted and/or signed, so it won't be human-readable.

### 2. Use the Audit Log Reader

To decrypt and verify signed audit events, use the Open Liberty Audit Log Reader:

```bash
# Build the audit reader
cd com.ibm.ws.security.audit.reader
gradle build

# Read encrypted/signed audit log
java -jar build/libs/auditReader.jar \
    --auditFileLocation=../build.image/wlp/usr/servers/defaultServer/logs/audit.log \
    --encrypted=true \
    --signed=true \
    --encKeyStoreLocation=../build.image/wlp/usr/servers/defaultServer/resources/security/AuditEncryptionKeyStore.p12 \
    --encKeyStorePassword=Liberty \
    --signingKeyStoreLocation=../build.image/wlp/usr/servers/defaultServer/resources/security/AuditSigningKeyStore.p12 \
    --signingKeyStorePassword=Liberty
```

## Audit Event Format

### Plain Audit Event

```json
{
  "type": "eventType",
  "eventName": "SECURITY_AUTHN",
  "outcome": "success",
  "reason": "200",
  "initiator": {
    "name": "testuser",
    "credential": {
      "type": "BASIC"
    }
  },
  "target": {
    "name": "/auditTest/",
    "appName": "auditTest",
    "typeURI": "service/application"
  },
  "observer": {
    "name": "defaultServer"
  },
  "eventTime": "2026-07-14T15:00:00.000Z"
}
```

### Encrypted Audit Event

Encrypted events are wrapped in an encryption envelope:

```json
{
  "encrypted": true,
  "encryptedData": "base64-encoded-encrypted-content",
  "algorithm": "AES/GCM/NoPadding",
  "keyAlias": "auditencryptionkey"
}
```

### Signed Audit Event

Signed events include a digital signature:

```json
{
  "signed": true,
  "signature": "base64-encoded-signature",
  "algorithm": "SHA256withRSA",
  "keyAlias": "auditsigningkey",
  "data": { ... original audit event ... }
}
```

### Both Encrypted and Signed

Events that are both encrypted and signed have both wrappers:

```json
{
  "encrypted": true,
  "signed": true,
  "encryptedData": "base64-encoded-encrypted-content",
  "signature": "base64-encoded-signature",
  "encryptionAlgorithm": "AES/GCM/NoPadding",
  "signatureAlgorithm": "SHA256withRSA",
  "encryptionKeyAlias": "auditencryptionkey",
  "signingKeyAlias": "auditsigningkey"
}
```

## Performance Considerations

### Encryption/Signing Overhead

- **Plain events**: ~20-50 events/second
- **Encrypted events**: ~15-30 events/second (20-40% slower)
- **Signed events**: ~10-25 events/second (30-50% slower)
- **Both encrypted and signed**: ~8-20 events/second (40-60% slower)

The overhead depends on:
- Key size (RSA 2048 vs 4096)
- Encryption algorithm (AES-128 vs AES-256)
- CPU performance
- I/O performance

### Recommendations

1. **For testing**: Use `--rate 10` to avoid overwhelming the server
2. **For production**: Monitor server CPU and adjust rate accordingly
3. **For large volumes**: Consider using multiple threads or instances

## Troubleshooting

### Issue: Keystores Not Found

**Error**: `CWWKS9104E: The keystore auditEncKeyStore cannot be found`

**Solution**: Ensure keystores exist at the correct location:
```bash
ls -la build.image/wlp/usr/servers/defaultServer/resources/security/
```

If missing, create them:
```bash
# Create encryption keystore
keytool -genkeypair -alias auditencryptionkey -keyalg RSA -keysize 2048 \
    -keystore AuditEncryptionKeyStore.p12 -storetype PKCS12 \
    -storepass Liberty -keypass Liberty \
    -dname "CN=Audit Encryption, O=IBM, C=US"

# Create signing keystore
keytool -genkeypair -alias auditsigningkey -keyalg RSA -keysize 2048 \
    -keystore AuditSigningKeyStore.p12 -storetype PKCS12 \
    -storepass Liberty -keypass Liberty \
    -dname "CN=Audit Signing, O=IBM, C=US"
```

### Issue: Server Won't Start

**Error**: Server fails to start after enabling encryption/signing

**Solution**: Check `messages.log` for errors:
```bash
tail -f build.image/wlp/usr/servers/defaultServer/logs/messages.log
```

Common issues:
- Incorrect keystore password
- Missing key alias
- Corrupted keystore

### Issue: Audit Events Not Generated

**Error**: No audit events appear in the log

**Solution**: 
1. Verify audit feature is enabled: `<feature>audit-1.0</feature>`
2. Check that auditFileHandler is configured
3. Ensure authentication is occurring (audit events require authentication)
4. Check server logs for audit service errors

### Issue: Cannot Decrypt/Verify Events

**Error**: Audit reader fails to decrypt or verify events

**Solution**:
1. Ensure you're using the correct keystores
2. Verify keystore passwords are correct
3. Check that key aliases match configuration
4. Ensure audit reader has access to keystores

## Examples

### Example 1: Generate 10,000 Encrypted and Signed Events

```bash
./generate-audit-events-advanced.sh \
    --mode both \
    --count 10000 \
    --rate 15
```

This will:
1. Configure server.xml for encrypted and signed audit events
2. Restart the server
3. Generate 10,000 audit events at 15 events/second
4. Take approximately 11 minutes to complete

### Example 2: Generate Events for 1 Hour

```bash
./generate-audit-events-advanced.sh \
    --mode both \
    --duration 3600 \
    --rate 10
```

This will generate approximately 36,000 encrypted and signed audit events over 1 hour.

### Example 3: Switch from Plain to Encrypted/Signed

```bash
# First, generate plain events
./generate-audit-events-advanced.sh --mode plain --count 1000

# Then switch to encrypted/signed
./generate-audit-events-advanced.sh --mode both --count 1000
```

The script automatically reconfigures the server between modes.

### Example 4: Manual Configuration (No Restart)

If you've already manually configured the server:

```bash
./generate-audit-events-advanced.sh \
    --mode both \
    --count 5000 \
    --no-restart
```

This skips the server restart step.

## Security Best Practices

1. **Protect Keystores**: Store keystores in a secure location with restricted permissions
2. **Use Strong Passwords**: Change default keystore passwords in production
3. **Rotate Keys**: Periodically rotate encryption and signing keys
4. **Backup Keys**: Maintain secure backups of keystores
5. **Monitor Access**: Log and monitor access to audit logs and keystores
6. **Separate Keys**: Use different keys for encryption and signing
7. **Key Size**: Use at least RSA 2048 or equivalent for production

## Additional Resources

- [Open Liberty Audit Documentation](https://openliberty.io/docs/latest/audit-events.html)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html)
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review server logs in `build.image/wlp/usr/servers/defaultServer/logs/`
3. Consult Open Liberty documentation
4. Open an issue on the Open Liberty GitHub repository