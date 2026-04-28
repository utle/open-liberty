# LTPA Keystore Auto-Conversion Implementation

## Overview
Implemented automatic conversion from `ltpa.keys` properties file format to `ltpa.p12` PKCS12 keystore format, eliminating the need for the `useKeystore` configuration attribute.

## Changes Made

### 1. LTPAKeyInfoManager.java

#### Added Constants
- `LTPA_KEYS_FILE_BACKUP_EXTENSION = ".file.backup"` - Extension for backing up ltpa.keys files during conversion

#### New Methods

##### `convertPropertiesToKeystore()`
Converts an existing ltpa.keys properties file to PKCS12 keystore format.
- Extracts keys from properties
- Creates PKCS12 keystore using LTPAKeystoreManager
- Stores keys in cache
- Location: Lines 580-640

##### `backupLtpaKeysFile()`
Backs up ltpa.keys file with `.file.backup` extension before conversion.
- Tries `.file.backup`, then `.file.backup-1`, `.file.backup-2`, etc.
- Logs backup location
- Location: Lines 515-540

#### Modified Method: `loadLtpaKeysFile()`

**New Flow for .p12 Files:**

1. **Check for ltpa.keys first**
   - If `ltpa.keys` exists:
     - Load properties from ltpa.keys
     - Handle version mismatches (FIPS/non-FIPS)
     - Convert to ltpa.p12 using `convertPropertiesToKeystore()`
     - Backup ltpa.keys to `ltpa.keys.file.backup`
     - Delete original ltpa.keys file
     - Return

2. **If ltpa.keys doesn't exist, check for ltpa.p12**
   - If `ltpa.p12` exists:
     - Load keys from keystore
     - Return
   
3. **If neither exists**
   - Create ltpa.p12 directly using `createPrimaryKeystore()`
   - Return

**Key Benefits:**
- Automatic migration from old format to new format
- Preserves original ltpa.keys as backup
- No configuration changes required
- Transparent to users

### 2. LTPAMessages.nlsprops

Added two new informational messages:

```properties
LTPA_KEYSTORE_CREATED_FROM_KEYS=CWWKS4128I: LTPA keystore created from existing ltpa.keys file: {0}
LTPA_KEYSTORE_CREATED_FROM_KEYS.explanation=The LTPA keys were successfully converted from the ltpa.keys properties file format to a PKCS12 keystore format.
LTPA_KEYSTORE_CREATED_FROM_KEYS.useraction=No action is required.

LTPA_KEYS_FILE_BACKED_UP=CWWKS4129I: LTPA keys file {0} backed up to {1} before conversion to keystore format.
LTPA_KEYS_FILE_BACKED_UP.explanation=The original ltpa.keys file was backed up before being converted to keystore format and then deleted.
LTPA_KEYS_FILE_BACKED_UP.useraction=No action is required. The backup file can be used to restore the original ltpa.keys file if needed.
```

## Behavior

### Scenario 1: Fresh Installation (No Files Exist)
- Server starts
- No ltpa.keys or ltpa.p12 found
- Creates ltpa.p12 directly with new keys
- Message: `CWWKS4122A: LTPA keystore created in X seconds. LTPA keystore file: ltpa.p12`

### Scenario 2: Existing ltpa.keys File
- Server starts
- Finds ltpa.keys
- Loads keys from ltpa.keys
- Converts to ltpa.p12
- Backs up ltpa.keys to ltpa.keys.file.backup
- Deletes original ltpa.keys
- Messages:
  - `CWWKS4128I: LTPA keystore created from existing ltpa.keys file: ltpa.p12`
  - `CWWKS4129I: LTPA keys file ltpa.keys backed up to ltpa.keys.file.backup before conversion`

### Scenario 3: Existing ltpa.p12 File
- Server starts
- No ltpa.keys found
- Finds ltpa.p12
- Loads keys from keystore
- Message: `CWWKS4123I: LTPA keys loaded from keystore: ltpa.p12`

### Scenario 4: Both Files Exist
- Server starts
- Finds ltpa.keys (takes precedence)
- Loads from ltpa.keys
- Converts to ltpa.p12 (overwrites existing)
- Backs up and deletes ltpa.keys
- Same messages as Scenario 2

## Migration Path

### For Users with ltpa.keys
1. No action required
2. On next server start, automatic conversion occurs
3. Original file backed up as ltpa.keys.file.backup
4. Server uses ltpa.p12 going forward

### For Users Already Using ltpa.p12
1. No change in behavior
2. Continues to use existing ltpa.p12

### For New Installations
1. ltpa.p12 created automatically
2. No ltpa.keys file created

## Configuration Changes

### Removed Attributes (No Longer Needed)
- `useKeystore` - Automatic detection based on file extension
- `keystoreFile` - Use `keysFileName` with .p12 extension
- `keystorePassword` - Use `keysPassword` for both formats

### Simplified Configuration

**Before:**
```xml
<ltpa keysFileName="ltpa.keys" 
      keysPassword="{xor}..." 
      useKeystore="true"
      keystoreFile="ltpa.p12"
      keystorePassword="{xor}..."/>
```

**After:**
```xml
<ltpa keysFileName="ltpa.p12" 
      keysPassword="{xor}..."/>
```

## Testing Recommendations

1. **Test Fresh Installation**
   - Delete all LTPA files
   - Start server
   - Verify ltpa.p12 created
   - Verify keys work for authentication

2. **Test Migration from ltpa.keys**
   - Start with existing ltpa.keys
   - Start server
   - Verify ltpa.p12 created
   - Verify ltpa.keys.file.backup exists
   - Verify original ltpa.keys deleted
   - Verify authentication still works

3. **Test Existing ltpa.p12**
   - Start with existing ltpa.p12
   - Start server
   - Verify no changes to ltpa.p12
   - Verify authentication works

4. **Test Version Mismatch**
   - Test FIPS/non-FIPS version handling
   - Verify proper warnings and regeneration

## Files Modified

1. `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java`
   - Added constants
   - Added `convertPropertiesToKeystore()` method
   - Added `backupLtpaKeysFile()` method
   - Modified `loadLtpaKeysFile()` method

2. `dev/com.ibm.ws.security.token.ltpa/resources/com/ibm/ws/security/token/ltpa/internal/resources/LTPAMessages.nlsprops`
   - Added CWWKS4128I message
   - Added CWWKS4129I message

## Next Steps

1. Compile and test the changes
2. Run FAT tests for LTPA functionality
3. Test migration scenarios
4. Update documentation to reflect simplified configuration
5. Consider deprecating useKeystore, keystoreFile, and keystorePassword attributes in future release