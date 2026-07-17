# Testing Guide for Audit RSA-OAEP Security Fix

## Overview

This guide provides step-by-step instructions for testing the RSA-OAEP security fix in Open Liberty's audit subsystem.

## Prerequisites

1. **Build the project** (first fix compilation errors):
   ```bash
   cd dev
   ./gradlew cnf:initialize
   ./gradlew assemble
   ```

2. **Verify build success**: Ensure `com.ibm.ws.security.audit.reader` and `com.ibm.ws.security.audit.source` compile without errors

## Test Scenarios

### Test 1: Verify New Logs Use RSA-OAEP

**Objective**: Confirm that newly generated audit logs include the RSA-OAEP algorithm tags.

**Steps**:

1. **Configure audit logging** in `server.xml`:
   ```xml
   <server>
       <featureManager>
           <feature>audit-1.0</feature>
       </featureManager>
       
       <auditFileHandler maxFiles="5" maxFileSize="20" compact="false">
           <keyStore id="auditEncKeyStore" 
                     location="auditEncryption.p12" 
                     type="PKCS12" 
                     password="Liberty"/>
           <keyStore id="auditSignKeyStore" 
                     location="auditSigning.p12" 
                     type="PKCS12" 
                     password="Liberty"/>
       </auditFileHandler>
       
       <audit encrypt="true" sign="true" 
              encryptAlias="auditencryption" 
              signingAlias="auditsigning"
              encryptKeyStoreRef="auditEncKeyStore"
              signingKeyStoreRef="auditSignKeyStore">
           <events name="AuditEvent_1"/>
       </audit>
   </server>
   ```

2. **Generate keystores** (if not already present):
   ```bash
   # Generate encryption keystore
   keytool -genkeypair -alias auditencryption -keyalg RSA -keysize 2048 \
           -validity 365 -keystore auditEncryption.p12 -storetype PKCS12 \
           -storepass Liberty -keypass Liberty \
           -dname "CN=Audit Encryption, O=IBM, C=US"
   
   # Generate signing keystore
   keytool -genkeypair -alias auditsigning -keyalg RSA -keysize 2048 \
           -validity 365 -keystore auditSigning.p12 -storetype PKCS12 \
           -storepass Liberty -keypass Liberty \
           -dname "CN=Audit Signing, O=IBM, C=US"
   ```

3. **Start the server**:
   ```bash
   ./bin/server start defaultServer
   ```

4. **Generate audit events** (trigger some security events, e.g., login attempts)

5. **Check the audit log header**:
   ```bash
   # The audit log will be in: wlp/usr/servers/defaultServer/logs/audit.log
   # Use a hex editor or the audit reader tool to inspect the header
   
   # Look for these tags in the binary header:
   # <keyWrapAlgorithm>RSA-OAEP</keyWrapAlgorithm>
   # <signingKeyWrapAlgorithm>RSA-OAEP</signingKeyWrapAlgorithm>
   ```

**Expected Result**: The audit log header should contain both algorithm tags with value "RSA-OAEP".

---

### Test 2: Read New Logs with Private Key

**Objective**: Verify that new logs can be decrypted using the private key.

**Steps**:

1. **Use the audit reader tool**:
   ```bash
   cd wlp/bin
   ./auditReader --auditFileLocation=../usr/servers/defaultServer/logs/audit.log \
                 --encrypted=true \
                 --signed=true \
                 --encKeyStoreLocation=../usr/servers/defaultServer/auditEncryption.p12 \
                 --encKeyStorePassword=Liberty \
                 --encKeyStoreType=PKCS12 \
                 --encCertAlias=auditencryption \
                 --signingKeyStoreLocation=../usr/servers/defaultServer/auditSigning.p12 \
                 --signingKeyStorePassword=Liberty \
                 --signingKeyStoreType=PKCS12 \
                 --signingCertAlias=auditsigning \
                 --outputFileLocation=../usr/servers/defaultServer/logs/audit-output.log
   ```

2. **Check the output**:
   ```bash
   cat ../usr/servers/defaultServer/logs/audit-output.log
   ```

**Expected Result**: 
- The audit reader should successfully decrypt and verify the log
- Output file should contain readable JSON audit records
- No errors about key decryption failures

---

### Test 3: Backward Compatibility with Legacy Logs

**Objective**: Verify that old logs (without RSA-OAEP tags) can still be read.

**Steps**:

1. **Obtain a legacy audit log** (one created before this fix, or create one by temporarily reverting the changes)

2. **Try reading it with the new reader**:
   ```bash
   ./auditReader --auditFileLocation=../usr/servers/defaultServer/logs/legacy-audit.log \
                 --encrypted=true \
                 --encKeyStoreLocation=../usr/servers/defaultServer/auditEncryption.p12 \
                 --encKeyStorePassword=Liberty \
                 --encKeyStoreType=PKCS12 \
                 --encCertAlias=auditencryption \
                 --outputFileLocation=../usr/servers/defaultServer/logs/legacy-output.log
   ```

**Expected Result**:
- Legacy logs should still be readable
- Reader should fall back to the old (insecure) public-key-only decryption path
- No errors or exceptions

---

### Test 4: Encryption-Only Logs

**Objective**: Test logs with encryption but no signing.

**Steps**:

1. **Configure server.xml** for encryption only:
   ```xml
   <audit encrypt="true" sign="false" 
          encryptAlias="auditencryption" 
          encryptKeyStoreRef="auditEncKeyStore">
       <events name="AuditEvent_1"/>
   </audit>
   ```

2. **Restart server and generate events**

3. **Read the log**:
   ```bash
   ./auditReader --auditFileLocation=../usr/servers/defaultServer/logs/audit.log \
                 --encrypted=true \
                 --encKeyStoreLocation=../usr/servers/defaultServer/auditEncryption.p12 \
                 --encKeyStorePassword=Liberty \
                 --encKeyStoreType=PKCS12 \
                 --encCertAlias=auditencryption \
                 --outputFileLocation=../usr/servers/defaultServer/logs/audit-output.log
   ```

**Expected Result**: Successfully decrypts records using RSA-OAEP.

---

### Test 5: Signing-Only Logs

**Objective**: Test logs with signing but no encryption.

**Steps**:

1. **Configure server.xml** for signing only:
   ```xml
   <audit encrypt="false" sign="true" 
          signingAlias="auditsigning"
          signingKeyStoreRef="auditSignKeyStore">
       <events name="AuditEvent_1"/>
   </audit>
   ```

2. **Restart server and generate events**

3. **Read the log**:
   ```bash
   ./auditReader --auditFileLocation=../usr/servers/defaultServer/logs/audit.log \
                 --signed=true \
                 --signingKeyStoreLocation=../usr/servers/defaultServer/auditSigning.p12 \
                 --signingKeyStorePassword=Liberty \
                 --signingKeyStoreType=PKCS12 \
                 --signingCertAlias=auditsigning \
                 --outputFileLocation=../usr/servers/defaultServer/logs/audit-output.log
   ```

**Expected Result**: Successfully verifies signatures using RSA-OAEP.

---

### Test 6: Verify Security Improvement

**Objective**: Demonstrate that the old vulnerability is fixed.

**Steps**:

1. **Generate a new audit log** with encryption enabled

2. **Extract the public key from the log header** (it's still there for backward compatibility)

3. **Try to decrypt using only the public key** (simulate the old attack):
   ```bash
   # This should FAIL with the new implementation
   # The old code would have succeeded because it derived the wrapping key from SHA-256(publicKey)
   ```

4. **Try to decrypt using the private key**:
   ```bash
   # This should SUCCEED
   ./auditReader --encrypted=true --encKeyStoreLocation=... (with private key access)
   ```

**Expected Result**:
- Decryption with only public key should fail (or not be possible)
- Decryption with private key should succeed
- This proves the encryption is now secure

---

## Automated Testing

### Unit Tests

If unit tests exist for the audit subsystem:

```bash
cd dev
./gradlew com.ibm.ws.security.audit.source:test
./gradlew com.ibm.ws.security.audit.reader:test
./gradlew com.ibm.ws.security.audit.file:test
```

### FAT Tests

If functional acceptance tests (FATs) exist:

```bash
./gradlew com.ibm.ws.security.audit*_fat*:buildandrun
```

---

## Debugging Tips

### Enable Debug Logging

Add to `server.xml`:
```xml
<logging traceSpecification="com.ibm.ws.security.audit.*=all:com.ibm.ws.security.audit.reader.*=all"/>
```

### Check for Algorithm Tags

Use this command to search for the algorithm tags in the binary log:
```bash
strings audit.log | grep -i "keyWrapAlgorithm"
```

### Verify Private Key Access

Ensure the audit reader has access to the private key:
```bash
keytool -list -v -keystore auditEncryption.p12 -storepass Liberty -storetype PKCS12
```

---

## Common Issues and Solutions

### Issue 1: Compilation Errors

**Problem**: `AuditLogReader.java` fails to compile with syntax errors.

**Solution**: Ensure the `getPrivateKey()` method is properly closed with `}` and there are no extra braces.

### Issue 2: "Cannot find private key" Error

**Problem**: Audit reader reports it cannot find the private key.

**Solution**: 
- Verify the keystore path is correct
- Verify the keystore password is correct
- Verify the alias matches the certificate in the keystore
- Ensure the keystore contains a private key (not just a certificate)

### Issue 3: Legacy Logs Don't Work

**Problem**: Old audit logs cannot be read after the fix.

**Solution**: This indicates the backward compatibility logic isn't working. Check that:
- The algorithm tag parsing correctly handles missing tags (sets to `null`)
- The branching logic checks for `"RSA-OAEP".equals(keyWrapAlgorithm)` (not just `keyWrapAlgorithm != null`)

### Issue 4: New Logs Don't Include Algorithm Tags

**Problem**: Newly generated logs don't have the RSA-OAEP tags.

**Solution**: 
- Verify `AuditFileHandler.java` was modified correctly
- Check that the constants were added
- Verify the tags are written in the `writeHeader()` method
- Rebuild the project completely

---

## Success Criteria

The fix is working correctly if:

✅ New audit logs include `<keyWrapAlgorithm>RSA-OAEP</keyWrapAlgorithm>` tags  
✅ New logs can be decrypted with private key  
✅ New logs CANNOT be decrypted with only public key  
✅ Legacy logs (without algorithm tags) still work  
✅ Encryption-only logs work  
✅ Signing-only logs work  
✅ Signed+encrypted logs work  
✅ No compilation errors  
✅ No runtime exceptions

---

## Quick Test Script

Here's a quick script to test the basic functionality:

```bash
#!/bin/bash
# Quick test script for RSA-OAEP audit fix

SERVER_DIR="wlp/usr/servers/defaultServer"
LOG_DIR="$SERVER_DIR/logs"

echo "=== Testing Audit RSA-OAEP Fix ==="

# 1. Check if audit log exists
if [ ! -f "$LOG_DIR/audit.log" ]; then
    echo "❌ No audit log found. Generate some audit events first."
    exit 1
fi

# 2. Check for RSA-OAEP tags
if strings "$LOG_DIR/audit.log" | grep -q "RSA-OAEP"; then
    echo "✅ Found RSA-OAEP algorithm tags in log"
else
    echo "❌ No RSA-OAEP tags found. Fix may not be working."
fi

# 3. Try to read the log
./wlp/bin/auditReader \
    --auditFileLocation="$LOG_DIR/audit.log" \
    --encrypted=true \
    --signed=true \
    --encKeyStoreLocation="$SERVER_DIR/auditEncryption.p12" \
    --encKeyStorePassword=Liberty \
    --encKeyStoreType=PKCS12 \
    --encCertAlias=auditencryption \
    --signingKeyStoreLocation="$SERVER_DIR/auditSigning.p12" \
    --signingKeyStorePassword=Liberty \
    --signingKeyStoreType=PKCS12 \
    --signingCertAlias=auditsigning \
    --outputFileLocation="$LOG_DIR/test-output.log"

if [ $? -eq 0 ]; then
    echo "✅ Successfully read and decrypted audit log"
    echo "✅ Output written to $LOG_DIR/test-output.log"
else
    echo "❌ Failed to read audit log"
    exit 1
fi

echo "=== Test Complete ==="
```

---

**Document Version**: 1.0  
**Last Updated**: 2026-07-16  
**Author**: IBM Bob (AI Assistant)