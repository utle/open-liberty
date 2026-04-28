# LTPA Keystore NullPointerException Fix

## Problem Analysis

### Root Cause
When the LTPA keystore file didn't exist yet, the code flow was:

1. `loadLtpaKeysFile()` called `isKeystoreFile("ltpa.p12")` → returned `true` (based on file extension)
2. `loadLtpaKeysFromKeystore()` was called
3. Inside that method, it checked if file exists, found it didn't exist, and returned early
4. Control returned to `loadLtpaKeysFile()` which also returned
5. **The code never reached the key generation logic**, leaving keys as `null`
6. Later, when trying to create token factory, NullPointerException occurred

### Error Stack Trace
```
java.lang.NullPointerException: Cannot invoke "[B.clone()" because "encodedKey" is null
    at com.ibm.ws.security.token.ltpa.LTPAPrivateKey.<init>(LTPAPrivateKey.java:45)
    at com.ibm.ws.security.token.ltpa.internal.LTPAKeyCreateTask.createTokenFactoryMap(LTPAKeyCreateTask.java:156)
```

## Solution

### Code Changes in LTPAKeyInfoManager.java

**Change 1: Check file existence before treating as keystore (lines 227-237)**

**Before:**
```java
// Check if this is a keystore file
if (isKeystoreFile(keyImportFile)) {
    loadLtpaKeysFromKeystore(locService, keyImportFile, keyPassword, validationKey, validUntilDateOdt);
    return;
}
```

**After:**
```java
// Check if this is a keystore file AND it exists
WsResource keystoreResource = null;
if (isKeystoreFile(keyImportFile)) {
    keystoreResource = getLTPAKeyFileResource(locService, keyImportFile);
    if (keystoreResource != null) {
        // Keystore file exists, load keys from it
        loadLtpaKeysFromKeystore(locService, keyImportFile, keyPassword, validationKey, validUntilDateOdt);
        return;
    }
    // Keystore file doesn't exist yet - fall through to key generation logic
}
```

**Change 2: Simplified loadLtpaKeysFromKeystore() (lines 690-699)**

Removed the file existence check since it's now done by the caller:

**Before:**
```java
// Get the keystore file resource
WsResource keystoreResource = getLTPAKeyFileResource(locService, keystoreFile);
if (keystoreResource == null) {
    // Keystore doesn't exist - this is OK, it will be created later
    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
        Tr.debug(this, tc, "Keystore file does not exist, will be created: " + keystoreFile);
    }
    return;
}

// Convert password bytes to char array
```

**After:**
```java
// Convert password bytes to char array
```

## Expected Behavior After Fix

### First Server Start (Keystore Doesn't Exist)
1. `isKeystoreFile("ltpa.p12")` returns `true` (based on extension)
2. `getLTPAKeyFileResource()` returns `null` (file doesn't exist)
3. Code falls through to normal key generation logic
4. New LTPA keys are generated
5. `createPrimaryKeystore()` is called to create the keystore with the new keys
6. Message logged: `CWWKS4122A: The LTPA keystore was created successfully`

### Subsequent Server Starts (Keystore Exists)
1. `isKeystoreFile("ltpa.p12")` returns `true`
2. `getLTPAKeyFileResource()` returns valid resource (file exists)
3. `loadLtpaKeysFromKeystore()` is called
4. Keys are loaded from existing keystore
5. Message logged: `CWWKS4123I: The LTPA keys were loaded successfully from keystore`

## Testing Required

After rebuilding the module, verify:

1. **Clean start**: Delete `ltpa.p12`, start server, verify:
   - Keystore file is created
   - CWWKS4122A message appears
   - No NullPointerException

2. **Restart**: Stop and restart server, verify:
   - Existing keystore is loaded
   - CWWKS4123I message appears
   - Server starts successfully

3. **Token validation**: Create and validate LTPA tokens to ensure keys work correctly

## Files Modified

- `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java`
  - Lines 227-237: Added file existence check before loading keystore
  - Lines 690-699: Removed redundant file existence check

## Build Command

```bash
export JAVA_HOME=/path/to/java21
export JAVA_21_HOME=/path/to/java21
cd dev
./gradlew com.ibm.ws.security.token.ltpa:clean com.ibm.ws.security.token.ltpa:build
```

## Status

- [x] Root cause identified
- [x] Code changes implemented
- [ ] Module rebuilt (requires Java environment)
- [ ] Runtime testing (requires Java environment)