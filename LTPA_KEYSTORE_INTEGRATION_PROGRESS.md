# LTPA Keystore Integration Progress

## Overview
This document tracks the integration of LTPA keystore support into Open Liberty, following the tWAS approach of storing keys without X.509 certificates.

## Completed Work

### 1. Foundation Classes (Completed)
- **LTPAKeys.java** - Simple data holder for LTPA key bytes (secretKey, privateKey, publicKey)
- **LTPAKeystoreManager.java** - Core keystore operations using null certificate chains (tWAS-compatible)
  - `createKeystore()` - Creates PKCS12 keystore with keys but no certificates
  - `loadKeysFromKeystore()` - Loads LTPA keys from existing keystore
  - `isValidKeystore()` - Validates keystore file

### 2. Configuration Interface Updates (Completed)
- **LTPAConfiguration.java** - Added new configuration constants and methods:
  - `CFG_KEY_KEYSTORE_FILE` - Keystore file location
  - `CFG_KEY_KEYSTORE_PASSWORD` - Keystore password
  - `CFG_KEY_USE_KEYSTORE` - Flag to enable keystore format
  - `getKeystoreFile()` - Getter for keystore file
  - `getKeystorePassword()` - Getter for keystore password
  - `getUseKeystore()` - Getter for keystore flag

### 3. Configuration Implementation Updates (Completed)
- **LTPAConfigurationImpl.java** - Added keystore configuration support:
  - Added fields: `keystoreFile`, `keystorePassword`, `useKeystore`
  - Updated `loadConfig()` to read keystore configuration from server.xml
  - Added `resolveKeystorePassword()` method with fallback logic:
    1. Check `keystorePassword` attribute in server.xml
    2. Check `keystore_password` environment variable
    3. Fall back to `primaryKeyPassword` if `useKeystore` is true
  - Implemented getter methods for keystore configuration

## Pending Work

### 4. LTPAKeyInfoManager Updates (Next)
Need to add keystore loading support:
- Add method to detect if file is keystore (.p12) vs .keys file
- Add method to load keys from keystore using LTPAKeystoreManager
- Update `loadLtpaKeysFile()` to check file type and route to appropriate loader
- Maintain backward compatibility with .keys files

### 5. LTPAKeyCreateTask Updates (Next)
Need to add keystore creation support:
- Check `useKeystore` configuration flag
- If true, create keystore instead of .keys file
- Use LTPAKeystoreManager.createKeystore() with generated keys
- Default keystore location: `${server.output.dir}/resources/security/ltpa.p12`

### 6. Message Keys (Next)
Add new message keys to LTPAMessages.nlsprops:
- `LTPA_KEYSTORE_CREATED` - Info message when keystore is created
- `LTPA_KEYSTORE_LOADED` - Info message when keys loaded from keystore
- `LTPA_KEYSTORE_ERROR` - Error message for keystore operations
- `LTPA_KEYSTORE_INVALID` - Error message for invalid keystore

### 7. Testing (Final)
- Test keystore creation on server startup
- Test key loading from keystore
- Test backward compatibility with .keys files
- Test configuration options
- Verify tWAS compatibility

## Technical Approach

### Key Design Decisions
1. **No X.509 Certificates**: Following tWAS, we store keys with null certificate chains
2. **Standard Java KeyStore API**: No external dependencies (no BouncyCastle)
3. **PKCS12 Format**: Industry standard, widely supported
4. **Backward Compatible**: Existing .keys files continue to work
5. **Configuration-Driven**: Users can choose keystore vs .keys file format

### Configuration Example
```xml
<ltpa 
    keysFileName="${server.output.dir}/resources/security/ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs="
    expiration="120m"
    useKeystore="true"
    keystoreFile="${server.output.dir}/resources/security/ltpa.p12"
    keystorePassword="{xor}Lz4sLCgwLTs=" />
```

### Default Behavior
- If `useKeystore="true"` and no `keystoreFile` specified: `${server.output.dir}/resources/security/ltpa.p12`
- If `useKeystore="true"` and no `keystorePassword` specified: Use `keysPassword`
- If `useKeystore="false"` or not specified: Use traditional .keys file format

## Build Status
- Module compiles successfully with new configuration fields
- No compilation errors
- Ready for next integration phase

## Next Steps
1. Update LTPAKeyInfoManager to support keystore loading
2. Update LTPAKeyCreateTask to support keystore creation
3. Add message keys for logging
4. Test end-to-end functionality
5. Document configuration options

## References
- tWAS Implementation: `/Users/utle/wasbld/WAS90.SERV1-f5282615.03/SERV1/ws/code/`
- Open Liberty Source: `/Users/utle/libertyGit/open-liberty/dev/com.ibm.ws.security.token.ltpa/`
- Design Documents: `LTPA_KEYSTORE_DESIGN_FINAL.md`, `LTPA_KEYSTORE_TWAS_ANALYSIS.md`