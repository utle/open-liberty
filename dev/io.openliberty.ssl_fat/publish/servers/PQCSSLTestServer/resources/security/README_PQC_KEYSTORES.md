# Post-Quantum Cryptography (PQC) Keystores for Testing

This directory contains keystores with PQC certificates for testing Liberty SSL PQC support.

## Overview

The following PQC algorithms are tested:
- **Dilithium (ML-DSA)**: NIST-selected digital signature algorithm
- **Kyber (ML-KEM)**: NIST-selected key encapsulation mechanism
- **SPHINCS+**: NIST-selected hash-based signature scheme

## Keystore Files

### Required Keystores

1. **dilithium_keystore.p12** - Contains Dilithium certificates
2. **kyber_keystore.p12** - Contains Kyber certificates
3. **sphincs_keystore.p12** - Contains SPHINCS+ certificates
4. **hybrid_keystore.p12** - Contains both traditional (RSA/ECDSA) and PQC certificates
5. **traditional_keystore.p12** - Contains traditional RSA/ECDSA certificates for comparison

All keystores use password: `pqcPassword123`

## Generating PQC Keystores

### Prerequisites

To generate PQC keystores, you need:

1. **BouncyCastle Provider** with PQC support (version 1.70+)
2. **OpenSSL with OQS Provider** (Open Quantum Safe)
3. **Java 11+** with security provider support

### Option 1: Using OpenSSL with OQS Provider

```bash
# Install liboqs and oqs-provider
# See: https://github.com/open-quantum-safe/liboqs
# See: https://github.com/open-quantum-safe/oqs-provider

# Generate Dilithium key and certificate
openssl req -x509 -new -newkey dilithium3 -keyout dilithium_key.pem \
    -out dilithium_cert.pem -nodes -subj "/CN=PQC Dilithium Test" \
    -days 365 -config openssl-pqc.cnf

# Convert to PKCS12
openssl pkcs12 -export -out dilithium_keystore.p12 \
    -inkey dilithium_key.pem -in dilithium_cert.pem \
    -password pass:pqcPassword123

# Generate Kyber key and certificate
openssl req -x509 -new -newkey kyber768 -keyout kyber_key.pem \
    -out kyber_cert.pem -nodes -subj "/CN=PQC Kyber Test" \
    -days 365 -config openssl-pqc.cnf

openssl pkcs12 -export -out kyber_keystore.p12 \
    -inkey kyber_key.pem -in kyber_cert.pem \
    -password pass:pqcPassword123

# Generate SPHINCS+ key and certificate
openssl req -x509 -new -newkey sphincssha2128ssimple -keyout sphincs_key.pem \
    -out sphincs_cert.pem -nodes -subj "/CN=PQC SPHINCS Test" \
    -days 365 -config openssl-pqc.cnf

openssl pkcs12 -export -out sphincs_keystore.p12 \
    -inkey sphincs_key.pem -in sphincs_cert.pem \
    -password pass:pqcPassword123
```

### Option 2: Using Java with BouncyCastle

```java
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import java.security.*;
import java.security.cert.X509Certificate;

// Add providers
Security.addProvider(new BouncyCastleProvider());
Security.addProvider(new BouncyCastlePQCProvider());

// Generate Dilithium keypair
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium3", "BCPQC");
KeyPair keyPair = kpg.generateKeyPair();

// Create self-signed certificate
// (Certificate generation code here)

// Store in PKCS12 keystore
KeyStore ks = KeyStore.getInstance("PKCS12");
ks.load(null, null);
ks.setKeyEntry("dilithium", keyPair.getPrivate(), 
               "pqcPassword123".toCharArray(), 
               new Certificate[]{cert});

// Save keystore
try (FileOutputStream fos = new FileOutputStream("dilithium_keystore.p12")) {
    ks.store(fos, "pqcPassword123".toCharArray());
}
```

### Option 3: Using Provided Script

A helper script is provided to generate all required keystores:

```bash
cd io.openliberty.ssl_fat/publish/servers/PQCSSLTestServer/resources/security
./generate_pqc_keystores.sh
```

## Hybrid Keystore

The hybrid keystore contains both traditional and PQC certificates:

```bash
# Create hybrid keystore with both RSA and Dilithium
keytool -genkeypair -alias rsa-key -keyalg RSA -keysize 2048 \
    -keystore hybrid_keystore.p12 -storetype PKCS12 \
    -storepass pqcPassword123 -dname "CN=Hybrid RSA"

# Import Dilithium certificate (requires PQC-enabled keytool)
keytool -importcert -alias dilithium-key -file dilithium_cert.pem \
    -keystore hybrid_keystore.p12 -storetype PKCS12 \
    -storepass pqcPassword123 -noprompt
```

## Traditional Keystore (for comparison)

```bash
# Generate traditional RSA keystore
keytool -genkeypair -alias rsa-key -keyalg RSA -keysize 2048 \
    -keystore traditional_keystore.p12 -storetype PKCS12 \
    -storepass pqcPassword123 -dname "CN=Traditional RSA Test" \
    -validity 365
```

## Verification

Verify keystores are created correctly:

```bash
# List keystore contents
keytool -list -v -keystore dilithium_keystore.p12 -storetype PKCS12 \
    -storepass pqcPassword123

# Check certificate details
openssl pkcs12 -in dilithium_keystore.p12 -passin pass:pqcPassword123 \
    -nokeys | openssl x509 -text -noout
```

## Testing

The keystores are used by:
- Unit tests: `com.ibm.ws.ssl/test/com/ibm/ws/ssl/config/PQCKeyStoreTest.java`
- FAT tests: `io.openliberty.ssl_fat/fat/src/io/openliberty/ssl/fat/PQCSSLTest.java`

## References

- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [BouncyCastle PQC](https://www.bouncycastle.org/java.html)
- [ML-DSA (Dilithium) Specification](https://csrc.nist.gov/pubs/fips/204/ipd)
- [ML-KEM (Kyber) Specification](https://csrc.nist.gov/pubs/fips/203/ipd)

## Notes

- PQC algorithms are still evolving; ensure you use the latest NIST-approved versions
- Key sizes for PQC algorithms are significantly larger than traditional algorithms
- Performance characteristics differ from traditional algorithms
- Hybrid mode is recommended for transition period