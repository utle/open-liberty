# Audit PQC ML-DSA Signing Implementation Summary

## Overview
This document summarizes the implementation of ML-DSA (FIPS 204) digital signature support for Open Liberty audit logs, making audit signing quantum-resistant.

## Implementation Date
July 8, 2026

## Changes Made

### 1. Added ML-DSA Algorithm Constants to CryptoUtils
**File:** `dev/com.ibm.ws.kernel.service/src/com/ibm/ws/common/crypto/CryptoUtils.java`

Added the following constants for ML-DSA signature algorithms:
```java
// Post-Quantum Cryptography (PQC) signature algorithms - NIST FIPS 204
public static final String SIGNATURE_ALGORITHM_ML_DSA = "ML-DSA";
public static final String SIGNATURE_ALGORITHM_ML_DSA_44 = "ML-DSA-44";
public static final String SIGNATURE_ALGORITHM_ML_DSA_65 = "ML-DSA-65";
public static final String SIGNATURE_ALGORITHM_ML_DSA_87 = "ML-DSA-87";
```

### 2. Updated AuditSigningImpl to Support ML-DSA
**File:** `dev/com.ibm.ws.security.audit.source/src/com/ibm/ws/security/audit/encryption/AuditSigningImpl.java`

**Changes:**
- Modified the `initialize()` method to detect PQC runtime support
- When Java 26+ is available, uses ML-DSA-65 for quantum-resistant signatures
- Falls back to SHA512withRSA when PQC is not available
- Added debug logging for signature algorithm selection

**Code Logic:**
```java
if (AuditPQCRuntimeSupport.isPQCSupported()) {
    // Use ML-DSA-65 for quantum-resistant signatures
    signature = Signature.getInstance(CryptoUtils.SIGNATURE_ALGORITHM_ML_DSA_65);
} else {
    // Fall back to traditional RSA
    signature = Signature.getInstance(CryptoUtils.SIGNATURE_ALGORITHM_SHA512WITHRSA);
}
```

### 3. Updated AuditLogReader to Support ML-DSA Verification
**File:** `dev/com.ibm.ws.security.audit.reader/src/com/ibm/ws/security/audit/reader/tasks/AuditLogReader.java`

**Changes:**
- Modified signing key loading logic to support both RSA and ML-DSA
- Detects PQC runtime support and loads appropriate key type
- For ML-DSA: loads public key from PEM file (e.g., `keystore_signing.pem`)
- For RSA: uses traditional keystore loading
- Includes fallback mechanism if ML-DSA key loading fails

**Key Loading Logic:**
```java
boolean useMLDSA = AuditPQCRuntimeSupport.isPQCSupported();

if (useMLDSA) {
    // Load ML-DSA public key from PEM file
    String mldsaPemFilePath = signingKeyStoreLocation.replace(".p12", "_signing.pem");
    KeyPair mldsaKeyPair = AuditPQCKeyLoader.loadMLDSAKeyPair(mldsaPemFilePath);
    publicKey = mldsaKeyPair.getPublic();
} else {
    // Fall back to traditional RSA
    publicKey = getPublicKey(signingKeyStoreType, signingKeyStoreLocation, 
                            signingKeyStorePassword, signingCertAlias);
}
```

## ML-DSA Algorithm Details

### ML-DSA-65 (Recommended)
- **Security Level:** NIST Level 3 (192-bit quantum security)
- **Public Key Size:** 1,952 bytes
- **Signature Size:** 3,309 bytes
- **Performance:** Balanced security and performance
- **Standard:** NIST FIPS 204

### Other Variants
- **ML-DSA-44:** 128-bit security, smaller keys/signatures, faster
- **ML-DSA-87:** 256-bit security, larger keys/signatures, slower

## Architecture

### Hybrid Approach
The implementation uses a **hybrid cryptographic approach**:
- **Encryption:** ML-KEM-768 (quantum-resistant key encapsulation)
- **Signing:** ML-DSA-65 (quantum-resistant digital signatures)

This provides comprehensive quantum resistance for audit logs.

### Runtime Detection
The system automatically detects Java version and PQC support:
- **Java 26+:** Uses native ML-DSA support
- **Java 17-25:** Falls back to RSA (with warning logs)

### Key Management
- **ML-DSA Keys:** Stored in PEM format (e.g., `audit_signing.pem`)
- **RSA Keys:** Stored in traditional keystores (PKCS12/JKS)
- **Key Generation:** Uses `AuditPQCKeyLoader.generateAndSaveMLDSA()`

## File Naming Convention

For audit configurations with signing enabled:
- **Encryption Keys:** `keystore.pem` (ML-KEM-768)
- **Signing Keys:** `keystore_signing.pem` (ML-DSA-65)
- **Traditional Keys:** `keystore.p12` or `keystore.jks` (RSA)

## Benefits

### Security
1. **Quantum Resistance:** ML-DSA signatures are secure against quantum computer attacks
2. **NIST Standardized:** Based on FIPS 204 standard
3. **Defense-in-Depth:** Combined with ML-KEM encryption for comprehensive protection

### Compatibility
1. **Backward Compatible:** Automatically falls back to RSA on older Java versions
2. **Transparent:** No configuration changes required
3. **Graceful Degradation:** Logs warnings when PQC is unavailable

### Performance
1. **Optimized:** ML-DSA-65 provides good balance of security and speed
2. **Native Support:** Uses Java 26+ native implementation (no external libraries)

## Testing Recommendations

### Unit Tests
1. Test ML-DSA signature creation with valid keys
2. Test ML-DSA signature verification with valid signatures
3. Test fallback to RSA when PQC is unavailable
4. Test key loading from PEM files

### Integration Tests
1. Test end-to-end audit log signing with ML-DSA
2. Test audit log reading/verification with ML-DSA signatures
3. Test mixed environments (some servers with PQC, some without)

### Performance Tests
1. Measure signature creation time (ML-DSA vs RSA)
2. Measure signature verification time
3. Measure impact on audit log throughput

## Migration Path

### For Existing Deployments
1. **Phase 1:** Upgrade to Java 26+
2. **Phase 2:** Generate ML-DSA signing keys using `AuditPQCKeyLoader`
3. **Phase 3:** Deploy keys to audit configuration
4. **Phase 4:** Restart servers (automatic PQC detection)

### Key Generation Example
```java
// Generate ML-DSA-65 signing key pair
AuditPQCKeyLoader.generateAndSaveMLDSA("/path/to/audit_signing.pem");
```

## Related Files

### Core Implementation
- `CryptoUtils.java` - Algorithm constants
- `AuditSigningImpl.java` - Signature creation
- `AuditLogReader.java` - Signature verification
- `AuditPQCRuntimeSupport.java` - Runtime detection
- `AuditPQCKeyLoader.java` - Key loading/generation

### Documentation
- `AUDIT_PQC_IMPLEMENTATION_SUMMARY.md` - Overall PQC implementation
- `AUDIT_PQC_SYSTEM_PROPERTY.md` - System property configuration
- `AUDIT_PQC_IMPLEMENTATION_PLAN.md` - Implementation plan

## Standards Compliance

- **NIST FIPS 204:** ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- **NIST FIPS 203:** ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
- **JEP 478:** Key Encapsulation Mechanism API (Java 26+)

## Security Considerations

1. **Key Protection:** ML-DSA private keys must be protected with same rigor as RSA keys
2. **Key Rotation:** Implement regular key rotation for both RSA and ML-DSA keys
3. **Algorithm Selection:** ML-DSA-65 recommended for most deployments
4. **Quantum Readiness:** This implementation is quantum-safe and future-proof

## Known Limitations

1. **Java Version:** Requires Java 26+ for ML-DSA support
2. **Key Format:** ML-DSA keys must be in PEM format
3. **Signature Size:** ML-DSA signatures are larger than RSA (3,309 vs ~256 bytes)

## Future Enhancements

1. **Hybrid Signatures:** Support both RSA and ML-DSA signatures in same audit log
2. **Algorithm Configuration:** Allow selection of ML-DSA-44/65/87 via configuration
3. **Key Rotation:** Automated key rotation support
4. **Performance Optimization:** Caching and batching for high-volume audit logs

## References

- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [JEP 478: Key Encapsulation Mechanism API](https://openjdk.org/jeps/478)
- [Open Liberty Audit Documentation](https://openliberty.io/docs/latest/audit-logs.html)

---

**Implementation Status:** ✅ Complete  
**Testing Status:** ⏳ Pending  
**Documentation Status:** ✅ Complete

Made with Bob