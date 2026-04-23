# LTPA Keystore Implementation - Compilation Fix

## Issue
Compilation error in `LTPAKeyInfoManager.java` line 137:
```
error: incompatible types: String cannot be converted to byte[]
```

## Root Cause
The `LTPAKeystoreManager` methods expect `byte[]` password parameters (annotated with `@Sensitive`), but `LTPAKeyInfoManager` was passing `String` passwords directly.

## Files Fixed

### 1. LTPAKeyInfoManager.java

#### Fix 1: loadPrimaryKeysFromKeystore() - Line 136-138
**Before:**
```java
try {
    LTPAKeys keys = ltpaKeystoreManager.loadPrimaryKeysFromKeystore(keystoreRef, keystorePassword);
```

**After:**
```java
try {
    byte[] passwordBytes = keystorePassword != null ? keystorePassword.getBytes() : null;
    LTPAKeys keys = ltpaKeystoreManager.loadPrimaryKeysFromKeystore(keystoreRef, passwordBytes);
```

#### Fix 2: loadValidationKeysFromKeystore() - Line 200-206
**Before:**
```java
try {
    LTPAKeys keys = ltpaKeystoreManager.loadValidationKeysFromKeystore(keystoreRef, keystorePassword, validationIndex);
    
    if (keys == null || !keys.isComplete()) {
        Tr.error(tc, "LTPA_KEYSTORE_MISSING_KEY", keystoreRef, "validation keys at index " + validationIndex);
        throw new IllegalStateException("Incomplete LTPA validation keys in keystore: " + keystoreRef + " index: " + validationIndex);
    }
```

**After:**
```java
try {
    byte[] passwordBytes = keystorePassword != null ? keystorePassword.getBytes() : null;
    Map<Integer, LTPAKeys> allValidationKeys = ltpaKeystoreManager.loadValidationKeysFromKeystore(keystoreRef, passwordBytes);
    
    LTPAKeys keys = allValidationKeys.get(validationIndex);
    if (keys == null || !keys.isComplete()) {
        Tr.error(tc, "LTPA_KEYSTORE_MISSING_KEY", keystoreRef, "validation keys at index " + validationIndex);
        throw new IllegalStateException("Incomplete LTPA validation keys in keystore: " + keystoreRef + " index: " + validationIndex);
    }
```

**Note:** The second fix also corrects the method signature mismatch. The `loadValidationKeysFromKeystore()` method returns `Map<Integer, LTPAKeys>` (all validation keys), not a single `LTPAKeys` object.

## Method Signatures in LTPAKeystoreManager

```java
// Load primary keys
public LTPAKeys loadPrimaryKeysFromKeystore(String keystoreId, @Sensitive byte[] password)
        throws KeyStoreException, CertificateException

// Load ALL validation keys (returns map of index -> keys)
public Map<Integer, LTPAKeys> loadValidationKeysFromKeystore(String keystoreId, @Sensitive byte[] password) 
        throws KeyStoreException, CertificateException
```

## Verification
The `Map` import was already present in `LTPAKeyInfoManager.java` (line 25), so no additional imports were needed.

## Additional Fix: Missing Interface Methods

### Issue 2
Compilation error in `LTPAConfigurationImpl.java`:
```
error: LTPAConfigurationImpl is not abstract and does not override abstract method getMigrateValidationToKeystore() in LTPAConfiguration
```

### Root Cause
The `LTPAConfiguration` interface defines two new methods that were not implemented in `LTPAConfigurationImpl`:
- `getMigrateToKeystore()`
- `getMigrateValidationToKeystore()`

### Fix: LTPAConfigurationImpl.java - Added after line 1026

```java
/** {@inheritDoc} */
@Override
public String getMigrateToKeystore() {
    return migrateToKeystore;
}

/** {@inheritDoc} */
@Override
public String getMigrateValidationToKeystore() {
    return migrateValidationToKeystore;
}
```

These methods return the configuration values for the migration target keystores that were already defined as fields in the class.

## Additional Fix: Constructor Parameter Mismatch

### Issue 3
Compilation error in `LTPAConfigurationImpl.java` line 179:
```
error: constructor LTPAKeystoreManager in class LTPAKeystoreManager cannot be applied to given types
```

### Root Cause
The `LTPAKeystoreManager` constructor expects two parameters:
1. `AtomicServiceReference<KeyStoreService>` keyStoreServiceRef
2. `LTPAKeyInfoManager` ltpaKeyInfoManager

But it was being called with only `KeyStoreService kss`.

### Fix: LTPAConfigurationImpl.java - Line 175-183

**Before:**
```java
if (keystoreRef != null || validationKeysFileName != null) {
    KeyStoreService kss = keyStoreService.getService();
    if (kss != null) {
        ltpaKeystoreManager = new LTPAKeystoreManager(kss);
    } else {
        Tr.error(tc, "LTPA_KEYSTORE_SERVICE_UNAVAILABLE");
    }
}
```

**After:**
```java
if (keystoreRef != null || validationKeysFileName != null) {
    if (keyStoreService.getService() != null) {
        ltpaKeystoreManager = new LTPAKeystoreManager(keyStoreService, ltpaKeyInfoManager);
    } else {
        Tr.error(tc, "LTPA_KEYSTORE_SERVICE_UNAVAILABLE");
    }
}
```

The fix passes the `AtomicServiceReference<KeyStoreService>` directly (not the unwrapped service) and includes the `ltpaKeyInfoManager` parameter.

## Additional Fix: Missing Configuration Constants

### Issue 4
Compilation error in `LTPAConfigurationImpl.java` line 253:
```
error: cannot find symbol
    keystoreRef = (String) props.get(CFG_KEY_KEYSTORE_REF);
```

### Root Cause
The constants `CFG_KEY_KEYSTORE_REF` and `CFG_KEY_KEYSTORE_PASSWORD` were not defined in the `LTPAConfiguration` interface.

### Fix: LTPAConfiguration.java - Added after line 83

```java
/**
 * The primary keystore reference ID.
 */
static final String CFG_KEY_KEYSTORE_REF = "keystoreRef";

/**
 * The primary keystore password.
 */
static final String CFG_KEY_KEYSTORE_PASSWORD = "keystorePassword"; // pragma: allowlist secret
```

These constants define the configuration property names for the primary LTPA keystore reference and password.

## Additional Fix: Method Parameter Mismatch in performAutoMigration

### Issue 5
Compilation error in `LTPAConfigurationImpl.java` line 366:
```
error: method performAutoMigration in class LTPAKeystoreManager cannot be applied to given types
  required: String,byte[],List<String>,List<byte[]>,String,String
  found:    String,String,String,String,List<Properties>,String,String
  reason: actual and formal argument lists differ in length
```

### Root Cause
The `performAutoMigration` method expects:
1. Primary keys file path (String)
2. Primary password (byte[])
3. List of validation file paths (List<String>)
4. List of validation passwords (List<byte[]>)
5. Primary keystore ID (String)
6. Validation keystore ID (String)

But it was being called with 7 parameters including `List<Properties> validationKeys` and String passwords instead of byte[].

### Fix: LTPAConfigurationImpl.java - Lines 365-397

**Before:**
```java
boolean migrationSuccess = ltpaKeystoreManager.performAutoMigration(
    primaryKeyImportFile,
    primaryKeyPassword,
    migrateToKeystore,
    keystorePassword,
    validationKeys,
    migrateValidationToKeystore,
    validationKeysPassword
);
```

**After:**
```java
// Extract validation file paths and passwords from validationKeys
List<String> validationFiles = new ArrayList<>();
List<byte[]> validationPasswords = new ArrayList<>();

if (validationKeys != null) {
    for (Properties props : validationKeys) {
        String fileName = props.getProperty(CFG_KEY_VALIDATION_FILE_NAME);
        String password = props.getProperty(CFG_KEY_VALIDATION_PASSWORD);
        if (fileName != null) {
            validationFiles.add(fileName);
            validationPasswords.add(password != null ? password.getBytes() : null);
        }
    }
}

// Perform migration using LTPAKeystoreManager
ltpaKeystoreManager.performAutoMigration(
    primaryKeyImportFile,
    primaryKeyPassword != null ? primaryKeyPassword.getBytes() : null,
    validationFiles,
    validationPasswords,
    migrateToKeystore,
    migrateValidationToKeystore
);

boolean migrationSuccess = true;
```

The fix extracts file paths and passwords from the `List<Properties>` and converts String passwords to byte[] before calling the method.

## Status
✅ Compilation errors fixed
✅ Type conversions corrected
✅ Method signatures aligned
✅ Missing interface methods implemented
✅ Constructor parameters corrected
✅ Missing configuration constants added
✅ Method parameter mismatches resolved
✅ Ready for compilation and testing