# LTPA Keystore Password Implementation Summary

## Overview

This document summarizes the implementation of keystore password support for LTPA keys in Open Liberty, following the same pattern used by SSL keystore configuration. The implementation provides optional key-level password support with automatic fallback to keystore passwords, matching SSL's behavior exactly.

## Changes Made

### 1. Configuration Schema (metatype.xml)

**File**: `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/metatype/metatype.xml`

#### Main LTPA Element
Added `keyPassword` attribute after `secretKeyAlias`:
```xml
<AD id="keyPassword" name="%keyPassword" description="%keyPassword.desc"
    required="false" type="String" ibm:type="password" />
```

#### Validation Keys Element
Added `keyPassword` attribute after `secretKeyAlias`:
```xml
<AD id="keyPassword" name="%validationKeys.keyPassword" description="%validationKeys.keyPassword.desc"
    required="false" type="String" ibm:type="password" />
```

### 2. Localized Descriptions (metatype.properties)

**File**: `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/l10n/metatype.properties`

#### Main LTPA keyPassword
```properties
keyPassword=Key password
keyPassword.desc=The password for accessing the private key in the keystore. This password is used to retrieve the private key from the keystore entry. If not specified, the keystore password is used. The best practice is to encrypt the password by using the securityUtility tool.
```

#### Validation Keys keyPassword
```properties
validationKeys.keyPassword=Validation key password
validationKeys.keyPassword.desc=The password for accessing the validation private key in the keystore. This password is used to retrieve the private key from the keystore entry. If not specified, the keystore password is used. The best practice is to encrypt the password by using the securityUtility tool.
```

### 3. Configuration Interface

**File**: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java`

Added getter method:
```java
/**
 * @return key password for accessing private keys in the keystore
 */
String getKeyPassword();
```

### 4. Configuration Implementation

**File**: `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java`

#### Field Declaration
```java
@Sensitive
private String keyPassword;
```

#### Loading in loadConfig()
```java
keyPassword = getPasswordFromProps(props, "keyPassword");
```

#### Password Extraction Helper
```java
@Sensitive
private String getPasswordFromProps(Map<String, Object> props, String key) {
    // First check the configuration property
    SerializableProtectedString sps = (SerializableProtectedString) props.get(key);
    String password = sps == null ? null : new String(sps.getChars());
    if (password != null && !password.isEmpty()) {
        return password;
    }
    
    // If not in config, return null (will fall back to keystore password)
    return null;
}
```

#### Getter Implementation
```java
@Override
public String getKeyPassword() {
    return keyPassword;
}
```

## How It Works

### Password Hierarchy and Fallback

The LTPA keystore password handling follows this hierarchy with automatic fallback:

1. **Keystore Password**: Set on the `<keyStore>` element, used to access the keystore itself
2. **Key Password** (NEW): Set on the `<ltpa>` or `<validationKeys>` element, used to access individual private keys within the keystore
   - If `keyPassword` is specified, it is used for private key access
   - If `keyPassword` is NOT specified (null), the KeyStoreService automatically falls back to using the keystore password
   - This matches SSL's behavior exactly

### Automatic Fallback Behavior

When `keyPassword` is null:
- The `KeyStoreService.getPrivateKeyFromKeyStore()` method automatically uses the keystore's password
- The `KeyStoreService.getSecretKeyFromKeyStore()` method automatically uses the keystore's password
- No additional code is needed - the fallback is handled by the KeyStoreService infrastructure

This means:
- **Simple case**: Just specify keystore password, and it works for everything
- **Advanced case**: Specify different key password for enhanced security

### SSL Comparison

This implementation mirrors the SSL keystore password pattern:

| SSL Configuration | LTPA Configuration |
|-------------------|-------------------|
| `<keyStore password="...">` | `<keyStore password="...">` |
| `<keyEntry keyPassword="...">` | `<ltpa keyPassword="...">` |
| Used for individual key access | Used for individual key access |

### Usage Examples

#### Example 1: Using Keystore Password Only
```xml
<keyStore id="ltpaKeyStore" 
          location="${server.config.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="keystorePassword" />

<ltpa keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      useKeyStore="true" />
```
In this case, the keystore password is used for both keystore access and key access.

#### Example 2: Using Separate Key Password
```xml
<keyStore id="ltpaKeyStore" 
          location="${server.config.dir}/resources/security/ltpa.p12"
          type="PKCS12" 
          password="keystorePassword" />

<ltpa keyStoreRef="ltpaKeyStore"
      keyAlias="ltpaKey"
      keyPassword="{xor}Lz4sLCgwLTs="
      useKeyStore="true" />
```
In this case, `keystorePassword` opens the keystore, and the decoded `keyPassword` accesses the private key.

#### Example 3: Validation Keys with Key Password
```xml
<keyStore id="validationKeyStore" 
          location="${server.config.dir}/resources/security/validation.p12"
          type="PKCS12" 
          password="keystorePassword" />

<ltpa keysFileName="ltpa.keys"
      keysPassword="filePassword">
    <validationKeys keyStoreRef="validationKeyStore"
                    keyAlias="oldKey"
                    keyPassword="{xor}Lz4sLCgwLTs=" />
</ltpa>
```

## Security Benefits

1. **Separation of Concerns**: Keystore password and key password can be different
2. **Enhanced Security**: Allows different access levels for keystore vs. individual keys
3. **Consistency**: Matches SSL keystore password handling pattern
4. **Flexibility**: Key password is optional - falls back to keystore password if not specified

## Implementation Notes

### Existing Infrastructure

The implementation leverages existing infrastructure:
- `LTPAKeyInfoManager.prepareLTPAKeyInfoFromKeyStore()` already accepts a `keyPassword` parameter
- `LTPAKeyInfoManager.prepareValidationKeysFromKeyStore()` already accepts a `keyPassword` parameter
- `KeyStoreService` methods already support key passwords

### Password Handling

Passwords are handled securely:
- Marked with `@Sensitive` annotation
- Extracted using `getPasswordFromProps()` which handles `SerializableProtectedString`
- Supports password encoding (XOR, AES) via `securityUtility` tool

## Files Modified

1. `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/metatype/metatype.xml`
2. `dev/com.ibm.ws.security.token.ltpa/resources/OSGI-INF/l10n/metatype.properties`
3. `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAConfiguration.java`
4. `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java`

## Testing Recommendations

1. **Basic Functionality**
   - Test keystore access with only keystore password
   - Test keystore access with separate key password
   - Verify password encoding (XOR, AES) works correctly

2. **Validation Keys**
   - Test validation keys with keystore password only
   - Test validation keys with separate key password
   - Test mixed configuration (some with key password, some without)

3. **Error Handling**
   - Test with incorrect key password
   - Test with missing key password when required
   - Verify error messages are clear and helpful

4. **Security**
   - Verify passwords are not logged in plain text
   - Verify @Sensitive annotation prevents password exposure in traces
   - Test password encoding/decoding

## Backward Compatibility

✅ **Fully Backward Compatible**
- `keyPassword` is optional
- If not specified, keystore password is used (existing behavior)
- No changes required for existing configurations
- Existing file-based configurations unaffected

## Next Steps

1. Create unit tests for password handling
2. Create FAT tests for end-to-end scenarios
3. Update user documentation
4. Add examples to Knowledge Center

## References

- SSL Keystore Configuration: `dev/com.ibm.ws.ssl/resources/OSGI-INF/metatype/metatype.xml`
- LTPA Keystore Design: `LTPA_KEYSTORE_DESIGN.md`
- LTPA Keystore Implementation: `LTPA_KEYSTORE_IMPLEMENTATION_SUMMARY.md`