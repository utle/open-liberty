# Audit RSA-OAEP Security Fix - Changes Summary

## Overview

This document provides a concise summary of all changes made to implement the RSA-OAEP security fix for Open Liberty's audit subsystem, ported from the tWAS audit handoff.

## Modified Files

### 1. AuditEncryptionImpl.java
**Path**: `dev/com.ibm.ws.security.audit.source/src/com/ibm/ws/security/audit/encryption/AuditEncryptionImpl.java`

**Changes**:
- Added `import javax.crypto.Cipher;`
- Replaced `encryptSharedKey()` method to use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` with public key
- Replaced `decryptSharedKey()` method to use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` with private key

**Lines Modified**: ~30 lines

### 2. AuditSigningImpl.java
**Path**: `dev/com.ibm.ws.security.audit.source/src/com/ibm/ws/security/audit/encryption/AuditSigningImpl.java`

**Changes**:
- Added `import javax.crypto.Cipher;`
- Replaced `encryptSharedKey()` method to use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` with public key
- Replaced `decryptSharedKey()` method to use `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` with private key

**Lines Modified**: ~30 lines

### 3. AuditFileHandler.java
**Path**: `dev/com.ibm.ws.security.audit.file/src/com/ibm/ws/security/audit/file/AuditFileHandler.java`

**Changes**:
- Added constant: `private static final String KEY_WRAP_ALGORITHM_TAG = "<keyWrapAlgorithm>RSA-OAEP</keyWrapAlgorithm>";`
- Added constant: `private static final String SIGNING_KEY_WRAP_ALGORITHM_TAG = "<signingKeyWrapAlgorithm>RSA-OAEP</signingKeyWrapAlgorithm>";`
- Added writing of `keyWrapAlgorithm` tag in `writeHeader()` method (line ~180)
- Added writing of `signingKeyWrapAlgorithm` tag in `writeHeader()` method (line ~190)

**Lines Added**: ~10 lines

### 4. AuditLogReader.java
**Path**: `dev/com.ibm.ws.security.audit.reader/src/com/ibm/ws/security/audit/reader/tasks/AuditLogReader.java`

**Changes**:

#### Static Fields (lines ~70-72)
- Added: `private static String keyWrapAlgorithm = null;`
- Added: `private static String signingKeyWrapAlgorithm = null;`

#### getEncryptionAndSigningData() Method (lines ~150-250)
- Added static field reset at method start (Bug 3 fix):
  ```java
  keyWrapAlgorithm = null;
  signingKeyWrapAlgorithm = null;
  ```
- Added parsing for `<keyWrapAlgorithm>` tag
- Added parsing for `<signingKeyWrapAlgorithm>` tag

#### getPrivateKey() Method (lines ~750-850)
- Added complete new method (100 lines) that mirrors `getPublicKey()` structure
- Retrieves private key from keystore instead of public key

#### processLog() Method - 4 Decrypt Call Sites
1. **Line ~310-330**: Signing key decryption (signed-only logs)
   - Changed from: `getPublicKey()` → `publicKey`
   - Changed to: Branch on `signingKeyWrapAlgorithm`, use `getPrivateKey()` if RSA-OAEP, else `getPublicKey()`

2. **Line ~445-465**: Encryption key decryption (encrypted-only logs)
   - Changed from: `getPublicKey()` → `publicKey`
   - Changed to: Branch on `keyWrapAlgorithm`, use `getPrivateKey()` if RSA-OAEP, else `getPublicKey()`

3. **Line ~595-615**: Signing key decryption (signed+encrypted logs)
   - Changed from: `getPublicKey()` → `publicKey`
   - Changed to: Branch on `signingKeyWrapAlgorithm`, use `getPrivateKey()` if RSA-OAEP, else `getPublicKey()`

4. **Line ~615-645**: Encryption key decryption (signed+encrypted logs)
   - Changed from: `getPublicKey()` → `publicKey`
   - Changed to: Branch on `keyWrapAlgorithm`, use `getPrivateKey()` if RSA-OAEP, else `getPublicKey()`

#### processRecord() Method (line ~875)
- Fixed Bug 4: Changed `indexOf(signatureCloseTag)` to `lastIndexOf(signatureCloseTag)`

**Lines Added**: ~150 lines  
**Lines Modified**: ~50 lines

## Bug Fixes

### Bug 3: Static Field Pollution
**Location**: `AuditLogReader.getEncryptionAndSigningData()`  
**Fix**: Reset static fields at method start to prevent values from one log polluting the next

### Bug 4: Signature Tag Parsing
**Location**: `AuditLogReader.processRecord()`  
**Fix**: Use `lastIndexOf` instead of `indexOf` for `</signature>` tag to handle signatures containing that string

## Total Impact

- **Files Modified**: 4
- **Total Lines Added**: ~190
- **Total Lines Modified**: ~110
- **New Methods**: 1 (`getPrivateKey()`)
- **Bug Fixes**: 2
- **Security Impact**: Critical

## Backward Compatibility

All changes maintain backward compatibility:
- New logs include `<keyWrapAlgorithm>RSA-OAEP</keyWrapAlgorithm>` tag
- Legacy logs without tag use old decryption path
- Reader automatically detects and handles both formats

## Testing Status

- [ ] Build verification
- [ ] Unit tests
- [ ] Functional tests with encrypted logs
- [ ] Functional tests with signed logs
- [ ] Functional tests with signed+encrypted logs
- [ ] Backward compatibility tests with legacy logs

## Related Documentation

- `AUDIT_RSA_OAEP_SECURITY_FIX.md` - Comprehensive security fix documentation
- `AUDIT_COMPARISON_DETAILED_GUIDE.md` - Detailed porting guide from tWAS
- Original tWAS handoff: `/Users/niyathar/Downloads/twas-audit-handoff/`

---

**Document Version**: 1.0  
**Last Updated**: 2026-07-16  
**Author**: IBM Bob (AI Assistant)