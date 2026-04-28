# LTPA Validation Keys Keystore Attributes Implementation

## Overview
Added `keystoreFile` and `keystorePassword` attributes to the `validationKeys` element in LTPA configuration, allowing users to specify PKCS12 keystore files directly for validation keys, similar to the primary LTPA keys.

## Changes Made

### 1. Metatype Configuration (metatype.xml)
**File:** `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/metatype/metatype.xml`

Added two new attributes to the `validationKeys` element:
- `validation.keystoreFile` - Path to PKCS12 keystore file containing validation keys
- `validation.keystorePassword` - Password for the validation keystore

Made `fileName` and `password` attributes optional (changed `required="true"` to `required="false"`).

### 2. Property Descriptions (metatype.properties)
**File:** `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/l10n/metatype.properties`

Added descriptions for the new attributes:
```properties
validation.keystoreFile=LTPA validation keystore file
validation.keystoreFile.desc=The path to the PKCS12 keystore file that contains the LTPA validation keys. This can be used as an alternative to fileName.

validation.keystorePassword=LTPA validation keystore password
validation.keystorePassword.desc=Password for the LTPA validation keystore. The best practice is to encrypt the password by using the securityUtility tool.
```

### 3. Configuration Constants (LTPAConfiguration.java)
**File:** `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java`

Added new constants:
```java
static final String CFG_KEY_VALIDATION_KEYSTORE_FILE = "validation.keystoreFile";
static final String CFG_KEY_VALIDATION_KEYSTORE_PASSWORD = "validation.keystorePassword";
```

### 4. Configuration Implementation (LTPAConfigurationImpl.java)
**File:** `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java`

#### Updated `getConfigValidationKeys` method call (lines 227-229)
Added new attribute keys to the method call:
```java
configValidationKeys = getConfigValidationKeys(validationKeysElements, CFG_KEY_VALIDATION_KEYS, 
    CFG_KEY_VALIDATION_FILE_NAME, CFG_KEY_VALIDATION_PASSWORD,
    CFG_KEY_VALIDATION_KEYSTORE_FILE, CFG_KEY_VALIDATION_KEYSTORE_PASSWORD, 
    CFG_KEY_VALIDATION_VALID_UNTIL_DATE);
```

#### Updated `getValidationKeysProps` method (lines 948-990)
- Added handling for `CFG_KEY_VALIDATION_KEYSTORE_PASSWORD` (SerializableProtectedString)
- Added path resolution for `CFG_KEY_VALIDATION_KEYSTORE_FILE`
- Changed validation logic to accept either (fileName + password) OR (keystoreFile + keystorePassword)
- Updated debug logging to show which type of file is being used

#### Updated `isConfiguredValidationKeys` method (lines 447-459)
Modified to check both `fileName` and `keystoreFile` when determining if a validation key is configured.

### 5. Key Loading Logic (LTPAKeyInfoManager.java)
**File:** `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java`

#### Updated validation key loading (lines 143-173)
Modified to prefer `keystoreFile` if specified, otherwise use `fileName`:
```java
// Determine which file to use - prefer keystoreFile if specified, otherwise use fileName
String filename = (String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_KEYSTORE_FILE);
if (filename == null) {
    filename = (String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_FILE_NAME);
}
```

#### Updated `getKeyPasswordBytes` method (lines 206-213)
Modified to prefer `keystorePassword` if specified, otherwise use `password`:
```java
// Prefer keystorePassword if specified, otherwise use password
String password = (String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_KEYSTORE_PASSWORD);
if (password == null) {
    password = (String) vKeys.get(LTPAConfiguration.CFG_KEY_VALIDATION_PASSWORD);
}
```

## Configuration Examples

### Option 1: Using .keys file (auto-converts to .p12)
```xml
<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}Lz4sLCgwLTs=">
    <validationKeys 
        fileName="validation1.keys"
        password="{xor}Lz4sLCgwLTs="/>
</ltpa>
```

### Option 2: Using .p12 keystore directly
```xml
<ltpa keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
      keystorePassword="{xor}Lz4sLCgwLTs=">
    <validationKeys 
        keystoreFile="validation1.p12"
        keystorePassword="{xor}Lz4sLCgwLTs="/>
</ltpa>
```

### Option 3: Mixed configuration
```xml
<ltpa keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keysPassword="{xor}Lz4sLCgwLTs=">
    <validationKeys 
        keystoreFile="validation1.p12"
        keystorePassword="{xor}Lz4sLCgwLTs="/>
</ltpa>
```

## Behavior

1. **Automatic Conversion**: If `fileName` is specified with a `.keys` file, it will be automatically converted to a `.p12` keystore file (same behavior as primary keys)

2. **Priority**: If both `keystoreFile` and `fileName` are specified, `keystoreFile` takes precedence

3. **Password Handling**: If both `keystorePassword` and `password` are specified, `keystorePassword` takes precedence

4. **Validation**: The configuration requires either:
   - `fileName` + `password`, OR
   - `keystoreFile` + `keystorePassword`

5. **Path Resolution**: Both `fileName` and `keystoreFile` paths are resolved relative to the primary LTPA keys directory

## Testing Required

1. Test with `fileName` and `password` (existing behavior)
2. Test with `keystoreFile` and `keystorePassword` (new behavior)
3. Test automatic conversion from `.keys` to `.p12` for validation keys
4. Test with multiple validation keys using different configurations
5. Verify error handling when neither set of attributes is provided
6. Test with `validUntilDate` attribute in combination with new attributes

## Status

✅ Metatype configuration updated
✅ Property descriptions added
✅ Configuration constants defined
✅ Configuration implementation updated
✅ Key loading logic updated
⏳ Compilation pending (requires JAVA_HOME setup)
⏳ Testing pending

## Next Steps

1. Set up Java environment (JAVA_HOME)
2. Compile the changes
3. Test all configuration scenarios
4. Verify backward compatibility with existing configurations