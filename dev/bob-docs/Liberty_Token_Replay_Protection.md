# Liberty Token Replay Protection Guide

## Overview

This document provides comprehensive guidance on protecting against token replay attacks in IBM WebSphere Liberty, where an attacker intercepts a valid token and attempts to reuse it from a different client or context.

## Table of Contents

1. [Understanding Token Replay Attacks](#understanding-token-replay-attacks)
2. [Built-in Replay Protection Mechanisms](#built-in-replay-protection-mechanisms)
3. [Token-Specific Protection Strategies](#token-specific-protection-strategies)
4. [Configuration Best Practices](#configuration-best-practices)
5. [Advanced Protection Techniques](#advanced-protection-techniques)
6. [Monitoring and Detection](#monitoring-and-detection)

---

## Understanding Token Replay Attacks

### What is a Token Replay Attack?

A token replay attack occurs when:
1. An attacker intercepts a valid authentication token (via network sniffing, XSS, or other means)
2. The attacker attempts to reuse the token from a different client, IP address, or browser
3. The goal is to impersonate the legitimate user without knowing their credentials

### Attack Vectors

- **Network Interception**: Man-in-the-middle attacks on unencrypted connections
- **Cross-Site Scripting (XSS)**: Stealing tokens from browser storage
- **Malware**: Token theft from compromised systems
- **Session Hijacking**: Taking over active sessions

---

## Built-in Replay Protection Mechanisms

### 1. JTI (JWT ID) Claim Protection

Liberty uses the `jti` (JWT ID) claim to prevent token reuse across all JWT-based tokens.

#### How It Works

```
Token Flow:
1. Token issued with unique jti: "abc123"
2. First use: Token validated, jti cached
3. Second use: jti found in cache → REJECTED
```

#### Implementation Details

**JTI Cache Structure:**
- Cache Key: `issuer:jti` (e.g., "https://idp.example.com:abc123")
- Cache Value: Token expiration time (milliseconds)
- Cache Size: 100,000 entries (default)
- Eviction: Automatic removal after token expiration

**Code Reference:**
```java
// From JtiNonceCache.java
protected String getCacheKey(JwtToken token) {
    Claims claims = token.getClaims();
    String jti = claims.getJwtId();
    String key = claims.getIssuer() + ":" + jti;
    return key;
}

public boolean contains(JwtToken token) {
    String key = getCacheKey(token);
    Long exp = (Long) primaryTable.get(key);
    if (exp != null && exp > currentTime) {
        return true; // Token already used - REPLAY DETECTED
    }
    primaryTable.put(key, tokenExpiration);
    return false; // First use - allowed
}
```

#### Configuration

**JWT Consumer (jwtConsumer):**
```xml
<jwtConsumer id="myConsumer"
    jtiCheckEnabled="true"
    tokenReuse="false"
    clockSkew="5m" />
```

**JWT Builder (jwtBuilder):**
```xml
<jwtBuilder id="myBuilder"
    jti="true"
    expiry="2h" />
```

**Key Parameters:**
- `jtiCheckEnabled`: Enable JTI replay detection (default: true)
- `tokenReuse`: Allow token reuse (default: false - recommended)
- `jti`: Generate unique JTI for each token (default: false)

---

### 2. Nonce-Based Protection (OIDC)

OpenID Connect uses nonces to bind tokens to specific authentication requests.

#### How It Works

```
Authentication Flow:
1. Client generates nonce: "xyz789"
2. Nonce stored in cookie/session
3. Authorization request includes nonce
4. ID Token returned with nonce claim
5. Client validates: nonce in token == stored nonce
6. Mismatch → REJECTED (potential replay)
```

#### Implementation

**Nonce Storage:**
```java
// From OidcStorageUtils.java
public static String createNonceStorageValue(String nonceValue, 
                                             String state, 
                                             String clientSecret) {
    return HashUtils.digest(nonceValue + state + clientSecret);
}
```

**Nonce Validation:**
```java
// From IdTokenValidator.java
public void validateNonce() {
    String cookieName = getNonceStorageKey(clientId, state);
    String expectedValue = createNonceStorageValue(nonce, state, secret);
    String storedValue = storage.get(cookieName);
    
    if (!expectedValue.equals(storedValue)) {
        throw new TokenValidationException("Nonce mismatch - potential replay");
    }
}
```

#### Configuration

```xml
<openidConnectClient id="myClient"
    nonceEnabled="true"
    useSession="true" />
```

---

### 3. SAML Assertion ID Caching

SAML responses use assertion ID caching to prevent replay attacks.

#### How It Works

```
SAML Flow:
1. SAML Response received with Assertion ID: "saml-123"
2. Check UnsolicitedResponseCache
3. If ID exists → REJECTED (replay detected)
4. If new → Cache ID and process assertion
```

#### Implementation

**Cache Check:**
```java
// From UnsolicitedHandler.java
UnsolicitedResponseCache resCache = 
    ssoService.getUnsolicitedResponseCache(providerName);
Assertion assertion = msgCtx.getValidatedAssertion();

if (resCache.isValid(assertion.getID())) {
    throw new SamlException("SAML20_RESPONSE_REPLAY",
        "The SAML assertion with ID [" + assertion.getID() + 
        "] has already been received");
}
```

#### Configuration

```xml
<samlWebSso20 id="mySaml"
    clockSkew="5m"
    tokenReplayTimeout="10m" />
```

---

## Token-Specific Protection Strategies

### JWT Tokens

**Multi-Layer Protection:**

1. **JTI Claim** (Primary)
   - Unique identifier per token
   - Cached until expiration
   - Prevents any reuse

2. **Short Expiration Times**
   ```xml
   <jwtBuilder expiry="15m" />
   ```

3. **Audience Restriction**
   ```xml
   <jwtBuilder audiences="https://api.example.com" />
   ```

4. **Issuer Validation**
   ```xml
   <jwtConsumer issuer="https://trusted-idp.example.com" />
   ```

**Example Configuration:**
```xml
<jwtBuilder id="secureBuilder"
    jti="true"
    expiry="15m"
    issuer="https://myapp.example.com"
    audiences="https://api.example.com" />

<jwtConsumer id="secureConsumer"
    jtiCheckEnabled="true"
    tokenReuse="false"
    clockSkew="2m"
    issuer="https://myapp.example.com"
    audiences="https://api.example.com" />
```

---

### LTPA Tokens

**Protection Mechanisms:**

1. **Cookie Attributes**
   ```xml
   <webAppSecurity
       httpOnlyCookies="true"
       sameSiteCookie="Strict"
       useOnlyCustomCookieName="true" />
   ```

2. **Short Token Lifetime**
   ```xml
   <ltpa expiration="30m" />
   ```

3. **HTTPS Enforcement**
   ```xml
   <webAppSecurity
       ssoRequiresSSL="true" />
   ```

**Limitations:**
- LTPA tokens do NOT have built-in JTI-style replay protection
- Rely on cookie security and short expiration
- Consider JWT for APIs requiring stronger replay protection

---

### OAuth/OIDC Tokens

**Access Token Protection:**

1. **Token Binding** (Proof-of-Possession)
   - Binds token to TLS channel
   - Prevents token theft effectiveness

2. **Sender-Constrained Tokens**
   - DPoP (Demonstrating Proof-of-Possession)
   - mTLS (Mutual TLS)

3. **Short-Lived Access Tokens**
   ```xml
   <oauth-roles>
       <authenticated>
           <special-subject type="ALL_AUTHENTICATED_USERS" />
       </authenticated>
   </oauth-roles>
   <localStore>
       <client ... accessTokenLifetime="900" />
   </localStore>
   ```

**ID Token Protection:**
- Nonce validation (automatic)
- JTI claim checking
- Audience validation

**Refresh Token Protection:**
- One-time use (rotation)
- Bound to client
- Revocation support

---

## Configuration Best Practices

### 1. Transport Security (Critical)

**Always Use HTTPS:**
```xml
<httpEndpoint id="defaultHttpEndpoint"
    httpPort="-1"
    httpsPort="9443">
    <tcpOptions soReuseAddr="true" />
    <httpOptions removeServerHeader="true" />
</httpEndpoint>

<ssl id="defaultSSLConfig"
    keyStoreRef="defaultKeyStore"
    trustStoreRef="defaultTrustStore"
    sslProtocol="TLSv1.3" />
```

**Enforce HTTPS for Cookies:**
```xml
<webAppSecurity
    ssoRequiresSSL="true"
    httpOnlyCookies="true"
    secureCookies="true" />
```

---

### 2. Token Expiration Strategy

**Recommended Expiration Times:**

| Token Type | Use Case | Recommended Expiration |
|------------|----------|------------------------|
| JWT (API) | Microservices | 15-30 minutes |
| JWT (User Session) | Web Application | 1-2 hours |
| LTPA | Traditional Web | 30-60 minutes |
| OAuth Access Token | API Access | 15-30 minutes |
| OAuth Refresh Token | Long-lived | 7-30 days |
| OIDC ID Token | Authentication | 1 hour |

**Configuration Example:**
```xml
<!-- Short-lived API tokens -->
<jwtBuilder id="apiToken"
    jti="true"
    expiry="15m" />

<!-- User session tokens -->
<jwtBuilder id="sessionToken"
    jti="true"
    expiry="1h" />

<!-- LTPA for web apps -->
<ltpa expiration="30m" />
```

---

### 3. Cookie Security

**Comprehensive Cookie Protection:**
```xml
<webAppSecurity
    httpOnlyCookies="true"
    secureCookies="true"
    sameSiteCookie="Strict"
    useOnlyCustomCookieName="true"
    ssoRequiresSSL="true"
    ssoCookieName="MySecureSSO" />
```

**Cookie Attributes Explained:**
- `httpOnlyCookies`: Prevents JavaScript access (XSS protection)
- `secureCookies`: Only sent over HTTPS
- `sameSiteCookie`: Prevents CSRF attacks
  - `Strict`: Never sent cross-site
  - `Lax`: Sent on top-level navigation
  - `None`: Requires `Secure` flag

---

### 4. Content Security Policy (CSP)

**Prevent Token Theft via XSS:**
```xml
<httpEndpoint id="defaultHttpEndpoint">
    <headers>
        <add>Content-Security-Policy: 
            default-src 'self'; 
            script-src 'self' 'nonce-%NONCE%'; 
            object-src 'none'; 
            base-uri 'self'
        </add>
    </headers>
</httpEndpoint>
```

---

## Advanced Protection Techniques

### 1. Token Binding to Client Context

**Concept:**
Bind tokens to specific client characteristics to prevent cross-client reuse.

**Implementation Approaches:**

#### A. IP Address Binding (Use with Caution)

**Pros:**
- Simple to implement
- Effective against remote attackers

**Cons:**
- Breaks with mobile clients
- Issues with NAT/proxy environments
- Not recommended for production

**Custom Implementation:**
```java
// Store IP in token claims
public String createBoundToken(String userId, String clientIp) {
    return JwtBuilder.create("myBuilder")
        .claim("sub", userId)
        .claim("client_ip", clientIp)
        .buildJwt()
        .compact();
}

// Validate IP on token use
public void validateToken(String token, String requestIp) {
    JwtToken jwt = JwtConsumer.create("myConsumer")
        .buildJwt(token);
    
    String tokenIp = jwt.getClaims().getClaim("client_ip");
    if (!tokenIp.equals(requestIp)) {
        throw new SecurityException("IP mismatch - potential replay");
    }
}
```

#### B. Device Fingerprinting

**Better Alternative:**
```java
// Generate device fingerprint
public String getDeviceFingerprint(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    String acceptLang = request.getHeader("Accept-Language");
    String acceptEnc = request.getHeader("Accept-Encoding");
    
    return hashOf(userAgent + acceptLang + acceptEnc);
}

// Include in token
.claim("device_fp", getDeviceFingerprint(request))
```

#### C. Certificate-Based Binding (Best)

**mTLS Token Binding:**
```xml
<ssl id="defaultSSLConfig"
    clientAuthentication="true"
    clientAuthenticationSupported="true" />

<jwtBuilder id="certBoundToken"
    jti="true">
    <claims>
        <claim name="cnf" value="${client.cert.thumbprint}" />
    </claims>
</jwtBuilder>
```

---

### 2. Proof-of-Possession (PoP) Tokens

**DPoP (Demonstrating Proof-of-Possession):**

```
Flow:
1. Client generates key pair
2. Client creates DPoP proof JWT signed with private key
3. DPoP proof includes:
   - Public key (jwk claim)
   - HTTP method and URL (htm, htu claims)
   - Timestamp (iat claim)
   - Unique identifier (jti claim)
4. Server validates DPoP proof matches access token
```

**Benefits:**
- Token useless without private key
- Prevents token theft effectiveness
- Standardized approach (RFC 9449)

---

### 3. Token Rotation Strategy

**Refresh Token Rotation:**
```xml
<oauth-roles>
    <authenticated>
        <special-subject type="ALL_AUTHENTICATED_USERS" />
    </authenticated>
</oauth-roles>

<localStore>
    <client name="myClient"
        secret="{xor}Lz4sLCgwLTs="
        displayname="My Application"
        enabled="true"
        accessTokenLifetime="900"
        refreshTokenLifetime="7200">
        <redirect>https://myapp.example.com/callback</redirect>
    </client>
</localStore>
```

**Rotation Logic:**
1. Use refresh token to get new access token
2. Invalidate old refresh token
3. Issue new refresh token
4. Old refresh token becomes one-time use

---

### 4. Rate Limiting and Anomaly Detection

**Detect Replay Attempts:**

```java
// Track token usage patterns
public class TokenUsageTracker {
    private Map<String, TokenUsageStats> usageStats;
    
    public void recordTokenUse(String jti, String clientIp) {
        TokenUsageStats stats = usageStats.get(jti);
        
        // Detect suspicious patterns
        if (stats.getUniqueIpCount() > 3) {
            // Same token from multiple IPs - potential replay
            alertSecurityTeam("Potential replay: " + jti);
        }
        
        if (stats.getRequestRate() > 100) {
            // Excessive requests - potential abuse
            blockToken(jti);
        }
    }
}
```

---

## Monitoring and Detection

### 1. Log Analysis

**Key Events to Monitor:**

```
# JWT replay detection
CWWKS6031E: The JSON Web Token (JWT) consumer [myConsumer] cannot process the token. 
The token has already been used.

# SAML replay detection
CWWKS5082E: The SAML assertion with ID [saml-123] has already been received, 
and cannot be accepted.

# OIDC nonce mismatch
CWWKS1751E: The OpenID Connect client [myClient] failed to validate the ID token 
because the nonce [xyz] in the token does not match the nonce that was specified 
in the request.
```

**Log Monitoring Configuration:**
```xml
<logging
    traceSpecification="*=info:com.ibm.ws.security.*=all"
    maxFileSize="100"
    maxFiles="10" />
```

---

### 2. Metrics and Alerting

**Track Key Metrics:**

1. **Token Reuse Attempts**
   - Count of JTI cache hits
   - Alert threshold: > 10/minute

2. **Failed Validations**
   - Nonce mismatches
   - Expired tokens
   - Invalid signatures

3. **Suspicious Patterns**
   - Same token from multiple IPs
   - High request rates per token
   - Tokens used after user logout

**Example Monitoring Query:**
```
# Splunk/ELK query
source="messages.log" 
"CWWKS6031E" OR "CWWKS5082E" OR "CWWKS1751E"
| stats count by jti, client_ip
| where count > 1
```

---

### 3. Security Incident Response

**When Replay Attack Detected:**

1. **Immediate Actions:**
   - Invalidate compromised token
   - Force user re-authentication
   - Block suspicious IP addresses

2. **Investigation:**
   - Review access logs
   - Identify attack vector
   - Assess data exposure

3. **Remediation:**
   - Rotate signing keys
   - Update security policies
   - Patch vulnerabilities

**Token Revocation:**
```java
// Revoke specific token
public void revokeToken(String jti) {
    // Add to revocation list
    tokenRevocationList.add(jti);
    
    // Force cache removal
    jtiCache.remove(jti);
    
    // Log security event
    auditLog.logSecurityEvent("TOKEN_REVOKED", jti);
}
```

---

## Security Checklist

### Essential Protections (Must Have)

- [ ] **HTTPS Only**: All token transmission over TLS 1.2+
- [ ] **JTI Enabled**: For all JWT tokens
- [ ] **Short Expiration**: 15-30 minutes for API tokens
- [ ] **HttpOnly Cookies**: Prevent XSS token theft
- [ ] **Secure Cookie Flag**: HTTPS-only transmission
- [ ] **SameSite Cookie**: Prevent CSRF attacks

### Recommended Protections (Should Have)

- [ ] **Nonce Validation**: For OIDC flows
- [ ] **Audience Validation**: Restrict token scope
- [ ] **Token Rotation**: For refresh tokens
- [ ] **Rate Limiting**: Prevent brute force
- [ ] **Logging**: Monitor replay attempts
- [ ] **CSP Headers**: Prevent XSS attacks

### Advanced Protections (Nice to Have)

- [ ] **Token Binding**: mTLS or DPoP
- [ ] **Device Fingerprinting**: Track client context
- [ ] **Anomaly Detection**: ML-based monitoring
- [ ] **Zero Trust**: Continuous validation
- [ ] **Token Revocation**: Real-time invalidation

---

## Common Pitfalls and Solutions

### Pitfall 1: Disabling JTI Checks

**Problem:**
```xml
<!-- INSECURE -->
<jwtConsumer jtiCheckEnabled="false" tokenReuse="true" />
```

**Solution:**
```xml
<!-- SECURE -->
<jwtConsumer jtiCheckEnabled="true" tokenReuse="false" />
```

---

### Pitfall 2: Long Token Lifetimes

**Problem:**
```xml
<!-- INSECURE - 24 hour tokens -->
<jwtBuilder expiry="24h" />
```

**Solution:**
```xml
<!-- SECURE - Short-lived with refresh -->
<jwtBuilder expiry="15m" />
<!-- Use refresh tokens for long sessions -->
```

---

### Pitfall 3: Insecure Cookie Configuration

**Problem:**
```xml
<!-- INSECURE -->
<webAppSecurity
    httpOnlyCookies="false"
    secureCookies="false"
    ssoRequiresSSL="false" />
```

**Solution:**
```xml
<!-- SECURE -->
<webAppSecurity
    httpOnlyCookies="true"
    secureCookies="true"
    sameSiteCookie="Strict"
    ssoRequiresSSL="true" />
```

---

### Pitfall 4: No Transport Security

**Problem:**
```xml
<!-- INSECURE - HTTP enabled -->
<httpEndpoint httpPort="9080" httpsPort="9443" />
```

**Solution:**
```xml
<!-- SECURE - HTTPS only -->
<httpEndpoint httpPort="-1" httpsPort="9443" />
```

---

## Testing Replay Protection

### Manual Testing

**Test 1: JWT Replay**
```bash
# Get token
TOKEN=$(curl -X POST https://server/token \
  -d "grant_type=password&username=user&password=pass" \
  | jq -r '.access_token')

# First use - should succeed
curl -H "Authorization: Bearer $TOKEN" \
  https://server/api/resource

# Second use - should fail with replay error
curl -H "Authorization: Bearer $TOKEN" \
  https://server/api/resource
```

**Expected Result:**
```
CWWKS6031E: The JSON Web Token (JWT) consumer cannot process the token. 
The token has already been used.
```

---

**Test 2: OIDC Nonce Validation**
```bash
# Capture authentication request with nonce
# Replay ID token with different nonce
# Should fail validation
```

---

### Automated Testing

**JUnit Test Example:**
```java
@Test
public void testJwtReplayPrevention() throws Exception {
    // Create token with JTI
    String token = createJwtWithJti();
    
    // First use - should succeed
    Response response1 = consumeToken(token);
    assertEquals(200, response1.getStatus());
    
    // Second use - should fail
    Response response2 = consumeToken(token);
    assertEquals(401, response2.getStatus());
    assertTrue(response2.getEntity().toString()
        .contains("token has already been used"));
}
```

---

## Conclusion

Protecting against token replay attacks requires a multi-layered approach:

1. **Primary Defense**: JTI claims and caching
2. **Transport Security**: HTTPS with proper TLS configuration
3. **Token Lifecycle**: Short expiration times
4. **Cookie Security**: HttpOnly, Secure, SameSite attributes
5. **Advanced Techniques**: Token binding, PoP, device fingerprinting
6. **Monitoring**: Active detection and response

**Key Takeaway**: No single mechanism provides complete protection. Implement multiple layers of defense appropriate to your security requirements and risk profile.

---

## References

- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [DPoP Specification (RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449)
- [OWASP Token Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Liberty Security Documentation: https://openliberty.io/docs/latest/reference/feature/jwt-1.0.html

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-15  
**Author**: IBM Liberty Security Team