# Audit Log RSA-OAEP Security Fix

## Overview

This document describes the critical security fix applied to Open Liberty's audit subsystem to address a vulnerability where audit log encryption was effectively worthless due to improper key wrapping.

## Vulnerability Description

### The Problem

The original implementation had a fundamental security flaw in how it encrypted the shared AES key used for audit log encryption:

1. **Broken Key Wrapping**: Instead of using proper RSA encryption, the code derived a wrapping key by computing `SHA-256(publicKeyBytes)` and using that as an AES key
2. **Public Key in Log Header**: The RSA public key was written to the audit log header in plaintext
3. **No Security**: Since anyone with the log file could extract the public key and derive the same wrapping key, the encryption provided zero security

### Impact

- Encrypted audit logs could be decrypted by anyone with access to the log file
- Signed audit logs could have their signing keys extracted
- The encryption and signing features provided a false sense of security

## The Fix

### RSA-OAEP Implementation

The fix replaces the broken key-wrapping mechanism with proper RSA-OAEP (Optimal Asymmetric Encryption Padding):

- **Encryption (Write Side)**: Uses RSA public key with OAEP padding to encrypt the shared AES key
- **Decryption (Read Side)**: Uses RSA private key with OAEP padding to decrypt the shared AES key
- **Algorithm**: `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

### Backward Compatibility

The fix maintains backward compatibility with existing audit logs:

- **New Logs**: Include `<keyWrapAlgorithm>RSA-OAEP</keyWrapAlgorithm>` tag in header
- **Legacy Logs**: Logs without this tag use the old (insecure) public-key-only decryption path
- **Reader Logic**: Branches on the presence/value of the algorithm tag to choose decryption method

## Files Modified

### Write Side (audit.source bundle)

1. **AuditEncryptionImpl.java**
   - `encryptSharedKey()`: Changed to use RSA-OAEP with public key
   - `decryptSharedKey()`: Changed to use RSA-OAEP with private key
   - Added `import javax.crypto.Cipher;`

2. **AuditSigningImpl.java**
   - `encryptSharedKey()`: Changed to use RSA-OAEP with public key
   - `decryptSharedKey()`: Changed to use RSA-OAEP with private key
   - Added `import javax.crypto.Cipher;`

3. **AuditFileHandler.java**
   - Added writing of `<keyWrapAlgorithm>RSA-OAEP</keyWrapAlgorithm>` tag
   - Added writing of `<signingKeyWrapAlgorithm>RSA-OAEP</signingKeyWrapAlgorithm>` tag

### Read Side (audit.reader bundle)

4. **AuditLogReader.java**
   - Added static fields: `keyWrapAlgorithm`, `signingKeyWrapAlgorithm`
   - Added static field reset in `getEncryptionAndSigningData()` (Bug 3 fix)
   - Added parsing for new algorithm tags in header
   - Added `getPrivateKey()` helper method (mirrors `getPublicKey()` structure)
   - Updated 4 decrypt call sites in `processLog()` to branch on algorithm:
     - Line ~312: Signing key decryption (signed-only logs)
     - Line ~446: Encryption key decryption (encrypted-only logs)
     - Line ~596: Signing key decryption (signed+encrypted logs)
     - Line ~616: Encryption key decryption (signed+encrypted logs)
   - Fixed Bug 4: Changed `indexOf` to `lastIndexOf` for `</signature>` tag (line 875)

## Technical Details

### Encryption Flow (Write Side)

```java
// New RSA-OAEP encryption
Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
c.init(Cipher.ENCRYPT_MODE, publicKey);
encryptedSharedKey = c.doFinal(encodedSharedKey);
```

### Decryption Flow (Read Side)

```java
// New RSA-OAEP decryption
Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
c.init(Cipher.DECRYPT_MODE, privateKey);
decryptedSharedKey = c.doFinal(encryptedSharedKey);
```

### Branching Logic

```java
Key decryptionKey;
if ("RSA-OAEP".equals(keyWrapAlgorithm)) {
    // New secure path: use private key
    decryptionKey = getPrivateKey(keyStoreType, keyStoreLocation, 
                                   keyStorePassword, certAlias);
} else {
    // Legacy path: use public key (insecure, for backward compatibility)
    decryptionKey = getPublicKey(keyStoreType, keyStoreLocation, 
                                  keyStorePassword, certAlias);
}
```

## Bug Fixes Included

### Bug 3: Static Field Pollution

**Problem**: Static fields `keyWrapAlgorithm` and `signingKeyWrapAlgorithm` were not reset between log reads, causing values from one log to pollute the next.

**Fix**: Added static field reset at the top of `getEncryptionAndSigningData()`:
```java
// Reset static fields to prevent pollution between log reads
keyWrapAlgorithm = null;
signingKeyWrapAlgorithm = null;
```

### Bug 4: Signature Tag Parsing

**Problem**: Used `indexOf` to find `</signature>` tag, which would fail if the signature data itself contained that string.

**Fix**: Changed to `lastIndexOf` to find the actual closing tag:
```java
int signatureCloseIdx = recordWithSignature.lastIndexOf(signatureCloseTag);
```

## Security Considerations

### Why RSA-OAEP?

- **Industry Standard**: RSA-OAEP is the recommended padding scheme for RSA encryption
- **Security Proof**: Has provable security properties under standard assumptions
- **Randomized**: Each encryption produces different ciphertext (unlike deterministic schemes)
- **Prevents Attacks**: Protects against chosen-ciphertext attacks

### Key Management

- **Public Key**: Used only for encryption (write side)
- **Private Key**: Required for decryption (read side)
- **Key Protection**: Private key must be protected with keystore password
- **Separation**: Reader requires private key access, which provides proper access control

## Testing

### Test Scenarios

1. **New Log Generation**: Verify new logs include RSA-OAEP tags
2. **New Log Reading**: Verify new logs can be decrypted with private key
3. **Legacy Log Reading**: Verify old logs still work (backward compatibility)
4. **Signing**: Verify signed logs work with RSA-OAEP
5. **Encryption**: Verify encrypted logs work with RSA-OAEP
6. **Both**: Verify signed+encrypted logs work with RSA-OAEP

### Test Commands

```bash
# Build the project
cd dev
./gradlew cnf:initialize
./gradlew assemble

# Run audit tests (if available)
./gradlew com.ibm.ws.security.audit.*:test
```

## Migration Guide

### For Existing Deployments

1. **Update Open Liberty**: Deploy the fixed version
2. **New Logs**: Will automatically use RSA-OAEP
3. **Old Logs**: Can still be read (backward compatible)
4. **Private Key**: Ensure audit reader has access to private key for new logs

### Configuration Changes

No configuration changes required. The fix is transparent to users:
- Write side automatically uses RSA-OAEP
- Read side automatically detects and handles both old and new formats

## References

### Source Files

- `dev/com.ibm.ws.security.audit.source/src/com/ibm/ws/security/audit/encryption/AuditEncryptionImpl.java`
- `dev/com.ibm.ws.security.audit.source/src/com/ibm/ws/security/audit/encryption/AuditSigningImpl.java`
- `dev/com.ibm.ws.security.audit.file/src/com/ibm/ws/security/audit/file/AuditFileHandler.java`
- `dev/com.ibm.ws.security.audit.reader/src/com/ibm/ws/security/audit/reader/tasks/AuditLogReader.java`

### Related Documentation

- `dev/AUDIT_COMPARISON_DETAILED_GUIDE.md`: Detailed porting guide from tWAS
- Original tWAS fix: `/Users/niyathar/Downloads/twas-audit-handoff/`

## Change Summary

### Statistics

- **Files Modified**: 4
- **Lines Added**: ~150
- **Lines Modified**: ~50
- **Bug Fixes**: 2 (static pollution, signature parsing)
- **Security Impact**: Critical - fixes complete encryption bypass

### Key Changes

1. ✅ RSA-OAEP encryption on write side (2 classes)
2. ✅ RSA-OAEP decryption on read side (4 call sites)
3. ✅ Algorithm tags in log header
4. ✅ Private key retrieval helper method
5. ✅ Backward compatibility for legacy logs
6. ✅ Static field pollution fix
7. ✅ Signature tag parsing fix

## Conclusion

This fix addresses a critical security vulnerability in the audit subsystem by replacing a fundamentally broken key-wrapping mechanism with industry-standard RSA-OAEP encryption. The implementation maintains backward compatibility while ensuring that all new audit logs are properly secured.

---

**Document Version**: 1.0  
**Last Updated**: 2026-07-16  
**Author**: IBM Bob (AI Assistant)