# LTPA Keystore Password Resolution Fix

## Problem Summary

When testing the LTPA keystore feature with a test server, the configuration failed with error:
```
CWWKS4118E: LTPA configuration error. A keysPassword attribute is not configured
```

Even though the `keysPassword` attribute WAS properly configured in server.xml as:
```xml
<ltpa keysPassword="{xor}Lz4sLCgwLTs=" keystoreFile="${server.output.dir}/resources/security/ltpa.p12"/>
```

## Root Cause

The bug was in [`LTPAConfigurationImpl.java`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java) line 217:

```java
keystorePassword = resolvePassword(props, CFG_KEY_KEYSTORE_PASSWORD);
```

This code attempted to resolve a password using the constant `CFG_KEY_KEYSTORE_PASSWORD` which maps to the attribute name `"keystorePassword"`. However, the LTPA keystore feature design **reuses the same `keysPassword` attribute** for both:
- Legacy `.keys` file format
- New PKCS12 keystore format

There is NO separate `keystorePassword` attribute in the metatype configuration, so the `resolvePassword()` method would always fail to find the password and throw an IllegalArgumentException.

## Solution Implemented

### 1. Added Configuration Validation

Added validation logic to ensure proper configuration:
- **Error if BOTH `keysFileName` and `keystoreFile` are configured** - Only one format can be used
- **Error if NEITHER is configured** - At least one must be specified
- **Reuse the same password** - `keystorePassword = primaryKeyPassword`

### 2. New Error Messages

Added two new error messages in [`LTPAMessages.nlsprops`](dev/com.ibm.ws.security.token.ltpa/resources/com/ibm/ws/security/token/ltpa/internal/resources/LTPAMessages.nlsprops):

```properties
LTPA_BOTH_KEYSFILE_AND_KEYSTORE_CONFIGURED=CWWKS4120E: LTPA configuration error. Both keysFileName and keystoreFile attributes are configured. Only one can be specified.
LTPA_BOTH_KEYSFILE_AND_KEYSTORE_CONFIGURED.explanation=The LTPA configuration cannot have both a legacy keys file and a keystore file configured at the same time.
LTPA_BOTH_KEYSFILE_AND_KEYSTORE_CONFIGURED.useraction=Configure either the keysFileName attribute for legacy .keys file format, or the keystoreFile attribute for PKCS12 keystore format, but not both.

LTPA_NEITHER_KEYSFILE_NOR_KEYSTORE_CONFIGURED=CWWKS4121E: LTPA configuration error. Neither keysFileName nor keystoreFile attribute is configured.
LTPA_NEITHER_KEYSFILE_NOR_KEYSTORE_CONFIGURED.explanation=The LTPA configuration requires either a legacy keys file or a keystore file to be specified.
LTPA_NEITHER_KEYSFILE_NOR_KEYSTORE_CONFIGURED.useraction=Configure either the keysFileName attribute for legacy .keys file format, or the keystoreFile attribute for PKCS12 keystore format.
```

### 3. Updated loadConfig() Method

Modified the `loadConfig()` method in [`LTPAConfigurationImpl.java`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java):

**Before:**
```java
private void loadConfig(Map<String, Object> props) {
    primaryKeyImportFile = (String) props.get(CFG_KEY_IMPORT_FILE);
    primaryKeyPassword = resolvePassword(props, CFG_KEY_PASSWORD);
    // ... other config ...
    keystoreFile = (String) props.get(CFG_KEY_KEYSTORE_FILE);
    keystorePassword = resolvePassword(props, CFG_KEY_KEYSTORE_PASSWORD);  // BUG!
```

**After:**
```java
private void loadConfig(Map<String, Object> props) {
    primaryKeyImportFile = (String) props.get(CFG_KEY_IMPORT_FILE);
    keystoreFile = (String) props.get(CFG_KEY_KEYSTORE_FILE);
    
    // Validate that only one of keysFileName or keystoreFile is configured
    boolean hasKeysFile = primaryKeyImportFile != null && !primaryKeyImportFile.trim().isEmpty();
    boolean hasKeystoreFile = keystoreFile != null && !keystoreFile.trim().isEmpty();
    
    if (hasKeysFile && hasKeystoreFile) {
        String formattedMessage = Tr.formatMessage(tc, "LTPA_BOTH_KEYSFILE_AND_KEYSTORE_CONFIGURED");
        throw new IllegalArgumentException(formattedMessage);
    }
    
    if (!hasKeysFile && !hasKeystoreFile) {
        String formattedMessage = Tr.formatMessage(tc, "LTPA_NEITHER_KEYSFILE_NOR_KEYSTORE_CONFIGURED");
        throw new IllegalArgumentException(formattedMessage);
    }
    
    // Resolve password - same password is used for both keys file and keystore
    primaryKeyPassword = resolvePassword(props, CFG_KEY_PASSWORD);
    keystorePassword = primaryKeyPassword;  // Keystore uses the same password
    
    // ... rest of config ...
```

## Changes Made

### Files Modified

1. **[`LTPAConfigurationImpl.java`](dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java)**
   - Lines 202-233: Added validation logic and fixed password resolution

2. **[`LTPAMessages.nlsprops`](dev/com.ibm.ws.security.token.ltpa/resources/com/ibm/ws/security/token/ltpa/internal/resources/LTPAMessages.nlsprops)**
   - Lines 101-108: Added CWWKS4120E and CWWKS4121E error messages

## Testing Required

1. **Recompile the LTPA module**
   ```bash
   cd dev
   ./gradlew com.ibm.ws.security.token.ltpa:build
   ```

2. **Test with keystore configuration**
   ```xml
   <ltpa keysPassword="{xor}Lz4sLCgwLTs=" 
         keystoreFile="${server.output.dir}/resources/security/ltpa.p12"/>
   ```
   - Should successfully create and load LTPA keystore
   - Should NOT throw CWWKS4118E error

3. **Test validation - both configured (should fail)**
   ```xml
   <ltpa keysPassword="{xor}Lz4sLCgwLTs=" 
         keysFileName="${server.output.dir}/resources/security/ltpa.keys"
         keystoreFile="${server.output.dir}/resources/security/ltpa.p12"/>
   ```
   - Should throw CWWKS4120E error

4. **Test validation - neither configured (should fail)**
   ```xml
   <ltpa keysPassword="{xor}Lz4sLCgwLTs="/>
   ```
   - Should throw CWWKS4121E error

## Design Rationale

The fix maintains the original design intent:
- **Single password attribute** - Simplifies configuration by reusing `keysPassword` for both formats
- **Mutual exclusivity** - Enforces that only one storage format can be active at a time
- **Clear error messages** - Provides actionable guidance when configuration is invalid
- **Backward compatibility** - Existing `.keys` file configurations continue to work unchanged

## Next Steps

1. Compile the changes
2. Run the test server to verify the fix
3. Run FAT tests to ensure no regressions
4. Update any documentation if needed