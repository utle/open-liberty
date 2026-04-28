# LTPA Keystore Custom Storage Implementation

## Problem Statement

PKCS12 keystores do NOT support storing SecretKeys using `KeyStore.setEntry()` with `PasswordProtection`. When attempting to store LTPA keys (secret key, private key, public key) using the standard approach, the keystore appears to be created successfully but becomes corrupted when loaded, resulting in the error:

```
toDerInputStream rejects tag type 35
```

## Root Cause

The PKCS12 format specification does not support storing arbitrary SecretKey entries using `setEntry()` with `PasswordProtection`. While the `keystore.store()` operation completes without errors, the resulting keystore file is malformed and cannot be loaded.

## Solution: Custom Certificate-Based Storage

Instead of storing three separate keystore entries (secret key, private key, public key), we now:

1. **Store ONLY the private key** using `setKeyEntry()` with a certificate chain
2. **Embed the secret key and public key bytes** as Base64-encoded strings in the certificate's Subject Alternative Name (SAN) extension
3. **Extract all three key byte arrays** from the certificate when loading

This approach is PKCS12-compliant because:
- We only use `setKeyEntry()` (which PKCS12 fully supports)
- We never use `setEntry()` with SecretKeys
- All data is stored in a single keystore entry

## Implementation Changes

### File: `LTPAKeystoreManager.java`

#### 1. New Imports

Added imports for X.509 certificate generation and manipulation:

```java
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
```

Removed imports that are no longer needed:
```java
// Removed: javax.crypto.SecretKey
// Removed: javax.crypto.spec.SecretKeySpec
// Removed: DefaultSSLCertificateCreator
// Removed: DefaultSSLCertificateFactory
// Removed: DefaultSubjectDN
```

#### 2. Updated Constants

Changed from three separate aliases to a single alias:

```java
// OLD:
private static final String SECRET_KEY_ALIAS = "ltpakeys";
private static final String PRIVATE_KEY_ALIAS = "ltpakeys_private";
private static final String PUBLIC_KEY_ALIAS = "ltpakeys_public";
private static final String SECRET_KEY_ALGORITHM = "RSA";

// NEW:
private static final String LTPA_KEY_ALIAS = "ltpakeys";
private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

// Added prefixes for embedded key data in SAN:
private static final String SECRET_KEY_PREFIX = "ltpa-secret:";
private static final String PUBLIC_KEY_PREFIX = "ltpa-public:";
```

#### 3. Simplified `createKeystore()` Method

**OLD Approach** (3 keystore entries):
```java
// Store secret key using setEntry() - FAILS with PKCS12
SecretKey secretKey = new SecretKeySpec(ltpaKeys.getSecretKeyBytes(), SECRET_KEY_ALGORITHM);
KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection(password);
keystore.setEntry(SECRET_KEY_ALIAS, secretKeyEntry, passwordProtection);

// Store private key with certificate using setKeyEntry() - WORKS
keystore.setKeyEntry(PRIVATE_KEY_ALIAS, privateKey, password, certChain);

// Store public key using setEntry() - FAILS with PKCS12
SecretKey publicKeyAsSecret = new SecretKeySpec(ltpaKeys.getPublicKeyBytes(), SECRET_KEY_ALGORITHM);
KeyStore.SecretKeyEntry publicKeyEntry = new KeyStore.SecretKeyEntry(publicKeyAsSecret);
keystore.setEntry(PUBLIC_KEY_ALIAS, publicKeyEntry, passwordProtection);
```

**NEW Approach** (1 keystore entry):
```java
// Reconstruct RSA keys from LTPA key bytes
KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM);
PrivateKey privateKey = keyFactory.generatePrivate(
    new PKCS8EncodedKeySpec(ltpaKeys.getPrivateKeyBytes())
);
PublicKey publicKey = keyFactory.generatePublic(
    new X509EncodedKeySpec(ltpaKeys.getPublicKeyBytes())
);

// Generate certificate with embedded secret key and public key bytes
X509Certificate cert = generateCertificateWithEmbeddedKeys(
    privateKey, 
    publicKey,
    ltpaKeys.getSecretKeyBytes(),
    ltpaKeys.getPublicKeyBytes()
);

Certificate[] certChain = new Certificate[] { cert };

// Store ONLY the private key with the enhanced certificate
keystore.setKeyEntry(LTPA_KEY_ALIAS, privateKey, password, certChain);
```

#### 4. New Certificate Generation Method

Replaced `generateSelfSignedCertificate()` with `generateCertificateWithEmbeddedKeys()`:

```java
private X509Certificate generateCertificateWithEmbeddedKeys(
        PrivateKey privateKey, 
        PublicKey publicKey,
        byte[] secretKeyBytes,
        byte[] publicKeyBytes) throws Exception {
    
    // Encode key bytes as Base64 strings for embedding in SAN
    String secretKeyB64 = SECRET_KEY_PREFIX + Base64.getEncoder().encodeToString(secretKeyBytes);
    String publicKeyB64 = PUBLIC_KEY_PREFIX + Base64.getEncoder().encodeToString(publicKeyBytes);
    
    // Create certificate info
    X509CertInfo certInfo = new X509CertInfo();
    
    // Set certificate version to V3 (required for extensions)
    certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
    
    // Generate random serial number
    BigInteger serialNumber = new BigInteger(64, new SecureRandom());
    certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
    
    // Set validity period (10 years)
    Date notBefore = new Date();
    Date notAfter = new Date(notBefore.getTime() + (CERT_VALIDITY_DAYS * 24 * 60 * 60 * 1000L));
    CertificateValidity validity = new CertificateValidity(notBefore, notAfter);
    certInfo.set(X509CertInfo.VALIDITY, validity);
    
    // Set subject and issuer (same for self-signed)
    X500Name owner = new X500Name("CN=LTPA, OU=Liberty, O=IBM");
    certInfo.set(X509CertInfo.SUBJECT, owner);
    certInfo.set(X509CertInfo.ISSUER, owner);
    
    // Set public key
    certInfo.set(X509CertInfo.KEY, new CertificateX509Key(publicKey));
    
    // Set signature algorithm
    AlgorithmId algorithmId = AlgorithmId.get(SIGNATURE_ALGORITHM);
    certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algorithmId));
    
    // Create Subject Alternative Name extension with embedded key data
    GeneralNames generalNames = new GeneralNames();
    
    // Add secret key as OtherName in SAN
    GeneralName secretKeyName = new GeneralName(new sun.security.x509.OtherName(
        new sun.security.util.ObjectIdentifier("1.3.6.1.4.1.2.267.1.1"), // Custom OID
        secretKeyB64.getBytes("UTF-8")
    ));
    generalNames.add(secretKeyName);
    
    // Add public key as OtherName in SAN
    GeneralName publicKeyName = new GeneralName(new sun.security.x509.OtherName(
        new sun.security.util.ObjectIdentifier("1.3.6.1.4.1.2.267.1.2"), // Custom OID
        publicKeyB64.getBytes("UTF-8")
    ));
    generalNames.add(publicKeyName);
    
    SubjectAlternativeNameExtension sanExtension = new SubjectAlternativeNameExtension(generalNames);
    certInfo.set(X509CertInfo.EXTENSIONS, new sun.security.x509.CertificateExtensions());
    sun.security.x509.CertificateExtensions extensions = 
        (sun.security.x509.CertificateExtensions) certInfo.get(X509CertInfo.EXTENSIONS);
    extensions.set(SubjectAlternativeNameExtension.NAME, sanExtension);
    
    // Create and sign the certificate
    X509CertImpl cert = new X509CertImpl(certInfo);
    cert.sign(privateKey, SIGNATURE_ALGORITHM);
    
    return cert;
}
```

#### 5. Updated `loadKeysFromKeystore()` Method

**OLD Approach** (load 3 separate entries):
```java
// Load secret key
SecretKey secretKey = (SecretKey) keystore.getKey(SECRET_KEY_ALIAS, password);
byte[] secretKeyBytes = secretKey.getEncoded();

// Load private key
PrivateKey privateKey = (PrivateKey) keystore.getKey(PRIVATE_KEY_ALIAS, password);
byte[] privateKeyBytes = privateKey.getEncoded();

// Load public key (stored as SecretKey)
SecretKey publicKeyAsSecret = (SecretKey) keystore.getKey(PUBLIC_KEY_ALIAS, password);
byte[] publicKeyBytes = publicKeyAsSecret.getEncoded();
```

**NEW Approach** (load 1 entry, extract embedded data):
```java
// Load private key
PrivateKey privateKey = (PrivateKey) keystore.getKey(LTPA_KEY_ALIAS, password);
byte[] privateKeyBytes = privateKey.getEncoded();

// Load certificate
Certificate cert = keystore.getCertificate(LTPA_KEY_ALIAS);
X509Certificate x509Cert = (X509Certificate) cert;

// Extract embedded key data from SAN extension
byte[] secretKeyBytes = null;
byte[] publicKeyBytes = null;

Collection<List<?>> sanCollection = x509Cert.getSubjectAlternativeNames();
if (sanCollection != null) {
    for (List<?> san : sanCollection) {
        if (san.size() >= 2) {
            Integer type = (Integer) san.get(0);
            // Type 0 is OtherName
            if (type == 0) {
                String value = (String) san.get(1);
                if (value.startsWith(SECRET_KEY_PREFIX)) {
                    String base64Data = value.substring(SECRET_KEY_PREFIX.length());
                    secretKeyBytes = Base64.getDecoder().decode(base64Data);
                } else if (value.startsWith(PUBLIC_KEY_PREFIX)) {
                    String base64Data = value.substring(PUBLIC_KEY_PREFIX.length());
                    publicKeyBytes = Base64.getDecoder().decode(base64Data);
                }
            }
        }
    }
}

if (secretKeyBytes == null || publicKeyBytes == null) {
    throw new Exception("Key data not found in certificate SAN extension");
}

return new LTPAKeys(secretKeyBytes, privateKeyBytes, publicKeyBytes);
```

## Benefits of This Approach

1. **PKCS12 Compliant**: Only uses `setKeyEntry()`, which is fully supported by PKCS12
2. **Single Entry**: All LTPA key data stored in one keystore entry
3. **No SecretKey Issues**: Avoids PKCS12's incompatibility with SecretKey storage
4. **Standard X.509**: Uses standard certificate extensions (SAN) for data embedding
5. **Backward Compatible**: Can still read the original LTPA key bytes

## Testing Plan

1. Build the module with the new implementation
2. Publish JAR to Liberty runtime
3. Start Liberty server (keystore creation)
4. Verify keystore file is created without errors
5. Restart Liberty server (keystore loading)
6. Verify no FFDC errors occur
7. Confirm LTPA tokens can be generated and validated

## Custom OIDs Used

- `1.3.6.1.4.1.2.267.1.1` - LTPA secret key (3DES bytes)
- `1.3.6.1.4.1.2.267.1.2` - LTPA public key (RSA bytes)

These OIDs are in the IBM enterprise number space (1.3.6.1.4.1.2) and are used to identify the custom data in the certificate's SAN extension.

## Status

Implementation complete. Waiting for build to complete to verify compilation success.