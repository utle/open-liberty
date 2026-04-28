# LTPA Keystore Testing Guide

## Overview
This guide provides comprehensive testing procedures for the LTPA keystore functionality in Open Liberty.

## Prerequisites

### 1. Build the Module
```bash
export JAVA_HOME=/path/to/java17
export JAVA_21_HOME=/path/to/java21
cd dev
./gradlew com.ibm.ws.security.token.ltpa:build
```

### 2. Create a Test Server
```bash
cd dev/build.image/wlp/bin
./server create testLTPAKeystore
```

## Test Scenarios

### Test 1: Keystore Creation on First Startup

**Objective:** Verify that Liberty creates a new LTPA keystore when configured with `useKeystore="true"` and no keystore exists.

**Configuration (server.xml):**
```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
    </featureManager>
    
    <ltpa 
        useKeystore="true"
        keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
        keystorePassword="{xor}Lz4sLCgwLTs="
        expiration="120m" />
</server>
```

**Steps:**
1. Ensure no keystore exists at the configured location
2. Start the server: `./server start testLTPAKeystore`
3. Check messages.log

**Expected Results:**
- ✅ Message: `CWWKS4103I: Creating the LTPA keys. This may take a few seconds.`
- ✅ Message: `CWWKS4122A: LTPA keystore created in X seconds. LTPA keystore file: .../ltpa.p12`
- ✅ Message: `CWWKS4105I: LTPA configuration is ready after X seconds.`
- ✅ Keystore file exists at configured location
- ✅ Keystore file size approximately 2-3 KB

**Verification Commands:**
```bash
# Check if keystore was created
ls -lh wlp/usr/servers/testLTPAKeystore/resources/security/ltpa.p12

# Verify keystore contents (requires keytool)
keytool -list -v -keystore wlp/usr/servers/testLTPAKeystore/resources/security/ltpa.p12 \
    -storepass password -storetype PKCS12
```

**Expected Keystore Contents:**
- Entry 1: `ltpaSecretKey` (SecretKeyEntry)
- Entry 2: `ltpaPrivateKey` (PrivateKeyEntry with null certificate chain)
- Entry 3: `ltpaPublicKey` (KeyEntry)

---

### Test 2: Keystore Loading on Subsequent Startups

**Objective:** Verify that Liberty loads existing LTPA keys from keystore on server restart.

**Prerequisites:** Complete Test 1 successfully

**Steps:**
1. Stop the server: `./server stop testLTPAKeystore`
2. Verify keystore still exists
3. Start the server: `./server start testLTPAKeystore`
4. Check messages.log

**Expected Results:**
- ✅ Message: `CWWKS4123I: LTPA keys loaded from keystore: .../ltpa.p12`
- ✅ Message: `CWWKS4105I: LTPA configuration is ready after X seconds.`
- ✅ No keystore creation messages
- ✅ Server starts faster than first startup (no key generation)

---

### Test 3: Invalid Keystore Password

**Objective:** Verify proper error handling when wrong keystore password is configured.

**Configuration (server.xml):**
```xml
<ltpa 
    useKeystore="true"
    keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
    keystorePassword="wrongpassword"
    expiration="120m" />
```

**Steps:**
1. Use existing keystore from Test 1
2. Change keystorePassword to incorrect value
3. Start the server

**Expected Results:**
- ✅ Message: `CWWKS4124E: LTPA keystore error. Unable to create or read LTPA keystore file: .../ltpa.p12. Exception: ...`
- ✅ Server fails to start or LTPA feature fails to initialize
- ✅ FFDC file created with detailed exception

---

### Test 4: Missing Keystore Password Configuration

**Objective:** Verify error when no password is configured for keystore mode.

**Configuration (server.xml):**
```xml
<ltpa 
    useKeystore="true"
    keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
    expiration="120m" />
```

**Steps:**
1. Remove keystorePassword attribute
2. Ensure no environment variables are set
3. Start the server

**Expected Results:**
- ✅ Message: `CWWKS4126E: LTPA keystore configuration error. A keystorePassword attribute is not configured...`
- ✅ Server fails to initialize LTPA
- ✅ Clear guidance in error message

---

### Test 5: Corrupted Keystore File

**Objective:** Verify error handling when keystore file is corrupted.

**Steps:**
1. Create valid keystore (Test 1)
2. Stop server
3. Corrupt the keystore file:
   ```bash
   echo "corrupted data" > wlp/usr/servers/testLTPAKeystore/resources/security/ltpa.p12
   ```
4. Start the server

**Expected Results:**
- ✅ Message: `CWWKS4124E: LTPA keystore error. Unable to create or read LTPA keystore file: .../ltpa.p12. Exception: ...`
- ✅ Or: `CWWKS4125E: The LTPA keystore file is invalid or corrupted: .../ltpa.p12`
- ✅ FFDC file with detailed exception

---

### Test 6: Keystore Password from Environment Variable

**Objective:** Verify keystore password can be provided via environment variable.

**Configuration (server.xml):**
```xml
<ltpa 
    useKeystore="true"
    keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
    expiration="120m" />
```

**Configuration (server.env):**
```bash
keystore_password=mySecurePassword123
```

**Steps:**
1. Remove existing keystore
2. Configure password in server.env
3. Start the server

**Expected Results:**
- ✅ Keystore created successfully
- ✅ Message: `CWWKS4122A: LTPA keystore created...`
- ✅ Server uses environment variable for password

---

### Test 7: Backward Compatibility with .keys Files

**Objective:** Verify traditional .keys files still work when useKeystore is false or not set.

**Configuration (server.xml):**
```xml
<ltpa 
    keysFileName="ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs="
    expiration="120m" />
```

**Steps:**
1. Remove any existing keystore
2. Remove any existing .keys file
3. Start the server

**Expected Results:**
- ✅ Message: `CWWKS4103I: Creating the LTPA keys...`
- ✅ Message: `CWWKS4104A: LTPA keys created in X seconds. LTPA key file: .../ltpa.keys`
- ✅ Traditional .keys file created (not keystore)
- ✅ No keystore-specific messages

---

### Test 8: Migration from .keys to Keystore

**Objective:** Verify smooth migration path from traditional .keys to keystore format.

**Steps:**
1. Start with traditional .keys configuration (Test 7)
2. Stop server
3. Change configuration to use keystore:
   ```xml
   <ltpa 
       useKeystore="true"
       keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
       keystorePassword="{xor}Lz4sLCgwLTs="
       expiration="120m" />
   ```
4. Start server

**Expected Results:**
- ✅ New keystore created with fresh keys
- ✅ Message: `CWWKS4122A: LTPA keystore created...`
- ✅ Old .keys file remains unchanged
- ✅ Server uses new keystore for LTPA operations

**Note:** Keys are NOT migrated automatically. This is intentional - users should coordinate key changes across cluster.

---

### Test 9: Keystore File Permissions

**Objective:** Verify keystore is created with appropriate file permissions.

**Steps:**
1. Create keystore (Test 1)
2. Check file permissions:
   ```bash
   ls -l wlp/usr/servers/testLTPAKeystore/resources/security/ltpa.p12
   ```

**Expected Results:**
- ✅ File permissions: `-rw-------` (600) or `-rw-r-----` (640)
- ✅ Owner: Server process user
- ✅ Not world-readable

---

### Test 10: Keystore in Custom Location

**Objective:** Verify keystore can be created in custom directory.

**Configuration (server.xml):**
```xml
<ltpa 
    useKeystore="true"
    keystoreFile="/custom/path/to/ltpa.p12"
    keystorePassword="{xor}Lz4sLCgwLTs="
    expiration="120m" />
```

**Steps:**
1. Ensure custom directory exists and is writable
2. Start server

**Expected Results:**
- ✅ Keystore created at custom location
- ✅ Message includes custom path
- ✅ Server can read/write to custom location

---

### Test 11: Keystore with Validation Keys

**Objective:** Verify keystore works with LTPA validation keys configuration.

**Configuration (server.xml):**
```xml
<ltpa 
    useKeystore="true"
    keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
    keystorePassword="{xor}Lz4sLCgwLTs="
    expiration="120m">
    
    <validationKeys 
        fileName="${server.output.dir}/resources/security/ltpa-validation.p12"
        password="{xor}Lz4sLCgwLTs="
        validUntilDate="2027-12-31T23:59:59Z" />
</ltpa>
```

**Steps:**
1. Create primary keystore
2. Create validation keystore manually or copy primary
3. Start server

**Expected Results:**
- ✅ Both keystores loaded successfully
- ✅ Message: `CWWKS4123I: LTPA keys loaded from keystore: .../ltpa.p12`
- ✅ Message: `CWWKS4123I: LTPA keys loaded from keystore: .../ltpa-validation.p12`
- ✅ Validation keys available for token validation

---

### Test 12: Performance Comparison

**Objective:** Compare startup time between .keys and keystore formats.

**Steps:**
1. Test with .keys file - measure startup time
2. Test with keystore - measure startup time
3. Compare results

**Expected Results:**
- ✅ Keystore startup time similar to .keys (within 10%)
- ✅ No significant performance degradation
- ✅ Both formats complete in < 5 seconds

---

## Automated Test Script

```bash
#!/bin/bash
# LTPA Keystore Test Runner

SERVER_NAME="testLTPAKeystore"
SERVER_DIR="wlp/usr/servers/$SERVER_NAME"
KEYSTORE_PATH="$SERVER_DIR/resources/security/ltpa.p12"

echo "=== LTPA Keystore Test Suite ==="

# Test 1: Keystore Creation
echo "Test 1: Keystore Creation"
rm -f "$KEYSTORE_PATH"
./server start $SERVER_NAME
sleep 5
if [ -f "$KEYSTORE_PATH" ]; then
    echo "✅ Test 1 PASSED: Keystore created"
else
    echo "❌ Test 1 FAILED: Keystore not created"
fi
./server stop $SERVER_NAME

# Test 2: Keystore Loading
echo "Test 2: Keystore Loading"
./server start $SERVER_NAME
sleep 5
grep "CWWKS4123I" "$SERVER_DIR/logs/messages.log" > /dev/null
if [ $? -eq 0 ]; then
    echo "✅ Test 2 PASSED: Keystore loaded"
else
    echo "❌ Test 2 FAILED: Keystore not loaded"
fi
./server stop $SERVER_NAME

echo "=== Test Suite Complete ==="
```

---

## Troubleshooting Guide

### Issue: Keystore not created
**Symptoms:** No CWWKS4122A message, no keystore file  
**Checks:**
1. Verify `useKeystore="true"` in server.xml
2. Check directory permissions
3. Verify password is configured
4. Check for FFDC files

### Issue: Cannot load keystore
**Symptoms:** CWWKS4124E error message  
**Checks:**
1. Verify keystore file exists
2. Check password is correct
3. Verify keystore is not corrupted
4. Check file permissions

### Issue: Wrong message keys appearing
**Symptoms:** Old message keys instead of new ones  
**Checks:**
1. Verify module was rebuilt with new message keys
2. Check Liberty installation includes updated module
3. Clear Liberty cache and restart

---

## Success Criteria

All tests should pass with:
- ✅ Correct message keys logged
- ✅ Keystore created/loaded successfully
- ✅ Proper error handling
- ✅ No FFDC files for normal operations
- ✅ Backward compatibility maintained
- ✅ Performance acceptable

---

## Next Steps After Testing

1. **Document Results:** Record test outcomes in test report
2. **File Issues:** Create issues for any failures
3. **Update Documentation:** Add keystore configuration to Liberty docs
4. **Translation:** Ensure message keys are translated
5. **Performance Testing:** Run under load to verify scalability

---

## Test Environment Details

**Liberty Version:** Open Liberty (development build)  
**Java Version:** Java 17 or Java 21  
**Operating System:** Linux, macOS, Windows, AIX, z/OS  
**Test Duration:** Approximately 30-45 minutes for full suite

---

## Contact

For questions or issues with testing:
- Review LTPA_KEYSTORE_MESSAGE_KEYS_SUMMARY.md
- Check LTPA_KEYSTORE_DESIGN_FINAL.md
- Consult Liberty documentation