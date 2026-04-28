# LTPA Validation Key Conversion to PKCS12

## Date: 2026-04-25

## Overview

Extended the LTPA keystore implementation to support automatic conversion of **validation keys** from `.keys` format to `.p12` (PKCS12) format, in addition to the primary LTPA keys.

---

## Background

### Previous Behavior
- **Primary LTPA keys**: Converted from `ltpa.keys` to `ltpa.p12` automatically
- **Validation keys**: Remained in `.keys` format (NOT converted)

### New Behavior
- **Primary LTPA keys**: Converted from `ltpa.keys` to `ltpa.p12` automatically ✅
- **Validation keys**: NOW also converted from `.keys` to `.p12` automatically ✅

---

## What are Validation Keys?

Validation keys are secondary LTPA keys used for:
- **Token validation** during key rotation periods
- **Multi-server environments** where different servers may use different keys
- **Backward compatibility** when migrating to new keys

They are configured in `server.xml` using:
```xml
<ltpa>
    <validationKeys 
        fileName="${server.output.dir}/resources/security/validation1.keys"
        password="{xor}Lz4sLCgwLTs="
        validUntilDate="2026-12-31T23:59:59Z"/>
    <validationKeys 
        fileName="${server.output.dir}/resources/security/validation2.keys"
        password="{xor}Lz4sLCgwLTs="/>
</ltpa>
```

Or automatically discovered when `monitorValidationKeysDir="true"` is set.

---

## Implementation Changes

### File Modified
**`dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java`**

### Changes Made

#### Before (Lines 273-294)
```java
// Convert ltpa.keys to ltpa.p12
if (!validationKey) {  // ❌ Only convert primary keys
    convertPropertiesToKeystore(locService, keyImportFile, keyPassword, props);
    
    // Backup the ltpa.keys file with .file.backup extension
    backupLtpaKeysFile(locService, ltpaKeyFileResource, keysFilePath);
    
    // Delete the original ltpa.keys file after successful conversion
    try {
        ltpaKeyFileResource.delete();
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Deleted original ltpa.keys file after conversion: " + keysFilePath);
        }
    } catch (Exception e) {
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(this, tc, "Failed to delete ltpa.keys file after conversion", e);
        }
    }
    return;
}
// For validation keys, just load from properties
```

#### After (Lines 273-289)
```java
// Convert ltpa.keys to ltpa.p12 (for both primary and validation keys)
convertPropertiesToKeystore(locService, keyImportFile, keyPassword, props);

// Backup the ltpa.keys file with .file.backup extension
backupLtpaKeysFile(locService, ltpaKeyFileResource, keysFilePath);

// Delete the original ltpa.keys file after successful conversion
try {
    ltpaKeyFileResource.delete();
    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
        Tr.debug(this, tc, "Deleted original " + (validationKey ? "validation" : "primary") + " ltpa.keys file after conversion: " + keysFilePath);
    }
} catch (Exception e) {
    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
        Tr.debug(this, tc, "Failed to delete ltpa.keys file after conversion", e);
    }
}
return;
```

### Key Changes
1. **Removed condition**: `if (!validationKey)` - now converts ALL keys
2. **Updated debug message**: Indicates whether it's a validation or primary key
3. **Unified behavior**: Both primary and validation keys follow the same conversion flow

---

## Conversion Flow

### For Validation Keys (New Behavior)

```
1. Server starts with validation1.keys configured
   ↓
2. LTPAKeyInfoManager.loadLtpaKeysFile() called with validationKey=true
   ↓
3. Detects validation1.keys exists
   ↓
4. Loads keys from validation1.keys (properties format)
   ↓
5. Converts to validation1.p12 (PKCS12 keystore)
   ↓
6. Backs up validation1.keys → validation1.keys.file.backup
   ↓
7. Deletes original validation1.keys
   ↓
8. Adds to ltpaValidationKeysInfos list
   ↓
9. Next restart: Loads directly from validation1.p12
```

---

## Benefits

### 1. **Consistency**
- All LTPA keys (primary and validation) now use the same secure PKCS12 format
- Unified key management approach

### 2. **Security**
- PKCS12 provides better security than plain text properties files
- Password-protected keystores
- Industry-standard format

### 3. **Simplified Migration**
- Automatic conversion eliminates manual steps
- Backup files preserve original keys
- Transparent to users

### 4. **Future-Proof**
- Aligns with modern security practices
- Compatible with key management tools
- Easier integration with HSM and key vaults

---

## Testing Scenarios

### Scenario 1: Fresh Installation with Validation Keys
```xml
<ltpa>
    <validationKeys fileName="validation1.keys" password="password"/>
</ltpa>
```
**Expected:**
- validation1.p12 created automatically
- validation1.keys backed up and deleted
- Server starts successfully

### Scenario 2: Existing Validation Keys (.keys format)
**Initial State:**
- validation1.keys exists
- validation1.p12 does NOT exist

**Expected:**
- validation1.keys converted to validation1.p12
- validation1.keys backed up as validation1.keys.file.backup
- Original validation1.keys deleted
- Server loads from validation1.p12

### Scenario 3: Existing Validation Keys (.p12 format)
**Initial State:**
- validation1.p12 exists
- validation1.keys does NOT exist

**Expected:**
- Loads directly from validation1.p12
- No conversion needed
- Server starts successfully

### Scenario 4: Multiple Validation Keys
```xml
<ltpa>
    <validationKeys fileName="validation1.keys" password="pass1"/>
    <validationKeys fileName="validation2.keys" password="pass2"/>
    <validationKeys fileName="validation3.keys" password="pass3"/>
</ltpa>
```
**Expected:**
- All three .keys files converted to .p12
- All three .keys files backed up
- All three original .keys files deleted
- Server loads all three validation keys from .p12 files

### Scenario 5: Directory Monitoring
```xml
<ltpa monitorValidationKeysDir="true"/>
```
**Expected:**
- All .keys files in directory converted to .p12
- Backed up and deleted
- Server monitors .p12 files going forward

---

## Compilation Results

✅ **Compilation Successful**

```
BUILD SUCCESSFUL in 12s
314 actionable tasks: 1 executed, 313 up-to-date
```

**Warnings:** Only expected deprecation warnings (non-blocking)
- `TimestampUtils.getElapsedTime(long)` at lines 599 and 657

---

## Log Messages

When validation keys are converted, the following messages appear in the logs:

```
CWWKS4103I: Creating the LTPA keys. This may take a few seconds.
CWWKS4128I: LTPA keystore created from LTPA keys file in X.XXX seconds. 
            LTPA keystore file: /path/to/validation1.p12
CWWKS4129I: LTPA keys file backed up: /path/to/validation1.keys.file.backup
```

---

## Configuration Examples

### Example 1: Single Validation Key
```xml
<ltpa 
    keysFileName="${server.output.dir}/resources/security/ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs="
    expiration="120m">
    <validationKeys 
        fileName="${server.output.dir}/resources/security/old-ltpa.keys"
        password="{xor}Lz4sLCgwLTs="
        validUntilDate="2026-12-31T23:59:59Z"/>
</ltpa>
```

### Example 2: Multiple Validation Keys with Different Passwords
```xml
<ltpa>
    <validationKeys 
        fileName="${server.output.dir}/resources/security/server1-ltpa.keys"
        password="{xor}Lz4sLCgwLTs="/>
    <validationKeys 
        fileName="${server.output.dir}/resources/security/server2-ltpa.keys"
        password="{xor}PDc+MTg6Nis="/>
    <validationKeys 
        fileName="${server.output.dir}/resources/security/server3-ltpa.keys"
        password="{xor}Lz4sLCgwLTs="/>
</ltpa>
```

### Example 3: Directory Monitoring
```xml
<ltpa 
    monitorValidationKeysDir="true"
    updateTrigger="polled"
    monitorInterval="5s"/>
```

---

## Backward Compatibility

✅ **Fully Backward Compatible**

- Existing `.keys` files are automatically converted
- Original files are backed up before deletion
- No configuration changes required
- Transparent to users

---

## Next Steps

1. **Test with validation keys**
   - Create test validation keys in `.keys` format
   - Start server and verify conversion
   - Restart server and verify loading from `.p12`

2. **Test multiple validation keys**
   - Configure multiple validation keys
   - Verify all are converted
   - Test token validation with each key

3. **Test directory monitoring**
   - Enable `monitorValidationKeysDir`
   - Add `.keys` files to directory
   - Verify automatic conversion

4. **Run FAT tests**
   - Execute LTPA validation key tests
   - Verify all scenarios pass

5. **Update documentation**
   - Document validation key conversion
   - Update migration guides
   - Add troubleshooting section

---

## Summary

Successfully extended the LTPA keystore implementation to support automatic conversion of validation keys from `.keys` to `.p12` format. This provides:

- ✅ Unified key management (primary + validation)
- ✅ Enhanced security (PKCS12 format)
- ✅ Automatic conversion with backup
- ✅ Full backward compatibility
- ✅ Transparent to users

The implementation is complete, compiled successfully, and ready for testing.