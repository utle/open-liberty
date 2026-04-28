# tWAS LTPA Keystore Implementation Analysis

## Key Discovery

After analyzing the tWAS source code, I discovered that **tWAS stores LTPA keys in keystores WITHOUT generating X.509 certificates**. This is the critical insight that solves our compilation problem.

## tWAS Architecture

### 1. Key Generation (LTPAKeyGenerator.java)
- Implements `com.ibm.websphere.crypto.KeyGenerator` interface
- Generates LTPA secret key (3DES or AES depending on FIPS mode)
- Uses `LTPACrypto.generateSharedKey()` to create the secret key
- Returns `javax.crypto.spec.SecretKeySpec` object

```java
ltpaSecretKey = new javax.crypto.spec.SecretKeySpec(
    crypto.generateSharedKey(), 0, size, algorithm
);
```

### 2. Key Storage (WSKeyStore.java)
- Uses standard Java KeyStore API
- Stores keys with **null certificate chain**
- Two key methods:
  - `setKeyEntry(alias, byte[] key, Certificate[] certChain)` - for raw key bytes
  - `setKeyEntry(alias, Key key, char[] password, Certificate[] certChain)` - for Key objects

```java
// From WSKeyStore.java line 1710
jKeyStore.setKeyEntry(alias, key, certChain);  // certChain can be null!
```

### 3. Key Export (LTPAServerObject.java)
- Retrieves keys from KeySetGroup
- Exports three types of keys:
  1. **Secret Key** (3DES/AES) - for token encryption
  2. **Private Key** (RSA) - for token signing
  3. **Public Key** (RSA) - for token verification

```java
// From LTPAServerObject.exportSSOProperties()
if (key instanceof java.security.Key) {
    tempSharedKey = ((java.security.Key)key).getEncoded();
    tmpShared = Base64Coder.base64Encode(encryptor.encrypt(tempSharedKey.clone()));
}
else if (key instanceof com.ibm.websphere.crypto.KeyPair) {
    java.security.Key publicKeyAsSecret = ((com.ibm.websphere.crypto.KeyPair)key).getPublicKey();
    tempLTPAPubKey = new LTPAPublicKey(publicKeyAsSecret.getEncoded());
    java.security.Key privateKeyAsSecret = ((com.ibm.websphere.crypto.KeyPair)key).getPrivateKey();
    tempLTPAPrivKey = new LTPAPrivateKey(privateKeyAsSecret.getEncoded());
}
```

## Implementation Strategy for Open Liberty

### What We DON'T Need
1. ❌ BouncyCastle library
2. ❌ X.509 certificate generation
3. ❌ sun.security.x509 classes
4. ❌ Custom certificate creation logic

### What We DO Need
1. ✅ Use standard Java KeyStore API
2. ✅ Store keys with null certificate chain
3. ✅ Use existing LTPA key generation from `LTPAKeyFileUtilityImpl.generateLTPAKeys()`
4. ✅ Store three key types:
   - Secret key as `SecretKeySpec`
   - Private key as `PrivateKey`
   - Public key as `PublicKey`

### Simplified Implementation

```java
// Create PKCS12 keystore
KeyStore keystore = KeyStore.getInstance("PKCS12");
keystore.load(null, password);

// Store secret key (no certificate chain needed!)
SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "DESede");
keystore.setEntry("ltpaSecretKey", 
    new KeyStore.SecretKeyEntry(secretKey),
    new KeyStore.PasswordProtection(password));

// Store private key (no certificate chain needed!)
keystore.setKeyEntry("ltpaPrivateKey", privateKey, password, null);

// Store public key as certificate (or as encoded bytes)
// Public keys typically need a certificate, but we can create a minimal one
// OR store as a separate entry

// Save keystore
try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
    keystore.store(fos, password);
}
```

## Key Differences from Initial Approach

| Aspect | Initial Approach | tWAS Approach |
|--------|-----------------|---------------|
| Certificate Generation | Required X.509 certs | No certificates needed |
| Library Dependencies | BouncyCastle | Standard Java only |
| Key Storage | Key + Certificate | Key with null cert chain |
| Complexity | High | Low |
| Compatibility | Unknown | Proven in tWAS |

## Next Steps

1. ✅ Verify current build compiles successfully
2. Update `LTPAKeystoreManager` to use null certificate chain approach
3. Remove all X.509 certificate generation code
4. Remove BouncyCastle dependency
5. Test keystore creation and key retrieval
6. Verify compatibility with tWAS keystores

## References

- tWAS LTPAKeyGenerator: `/Users/utle/wasbld/WAS90.SERV1-f5282615.03/SERV1/ws/code/security.impl/src/com/ibm/ws/security/ltpa/LTPAKeyGenerator.java`
- tWAS LTPAServerObject: `/Users/utle/wasbld/WAS90.SERV1-f5282615.03/SERV1/ws/code/security.impl/src/com/ibm/ws/security/ltpa/LTPAServerObject.java`
- tWAS WSKeyStore: `/Users/utle/wasbld/WAS90.SERV1-f5282615.03/SERV1/ws/code/security.crypto/src/com/ibm/ws/ssl/config/WSKeyStore.java`