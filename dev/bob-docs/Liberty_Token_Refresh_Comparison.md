# Liberty Security Token Refresh - Comparison Guide

## Overview

This document compares how different security token types in IBM WebSphere Liberty handle token refresh, including LTPA, OAuth/OIDC, JWT, and SPNEGO tokens.

## Table of Contents
1. [Token Refresh Comparison Matrix](#token-refresh-comparison-matrix)
2. [LTPA Token Refresh](#ltpa-token-refresh)
3. [OAuth/OIDC Token Refresh](#oauthoidc-token-refresh)
4. [JWT Token Refresh](#jwt-token-refresh)
5. [SPNEGO Token Refresh](#spnego-token-refresh)
6. [Jakarta Security Token Refresh](#jakarta-security-token-refresh)
7. [Best Practices](#best-practices)

---

## Token Refresh Comparison Matrix

| Feature | LTPA | OAuth/OIDC | JWT | SPNEGO | Jakarta Security |
|---------|------|------------|-----|--------|------------------|
| **Automatic Refresh** | ✅ Yes | ✅ Yes (with refresh_token) | ❌ No | ❌ No | ✅ Yes (configurable) |
| **Refresh Threshold** | ✅ Configurable | ❌ N/A | ❌ N/A | ❌ N/A | ✅ Implicit |
| **Max Lifetime** | ✅ Yes | ✅ Yes | ✅ Via exp claim | ✅ Via Kerberos ticket | ✅ Yes |
| **Refresh Token** | ❌ N/A | ✅ Separate token | ❌ N/A | ❌ N/A | ✅ Separate token |
| **Server-Side Refresh** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ✅ Yes |
| **Client-Side Refresh** | ❌ No | ✅ Yes | ❌ No | ✅ Yes (re-auth) | ✅ Yes |
| **Refresh Triggers** | Time-based | Explicit request | N/A | Expiration | Time-based |
| **Cookie Update** | ✅ Automatic | ✅ Automatic | ❌ N/A | ❌ N/A | ✅ Automatic |

---

## LTPA Token Refresh

### Mechanism

LTPA tokens support **automatic server-side refresh** based on configurable thresholds.

### Configuration

```xml
<ltpa 
    expiration="15m"           <!-- Initial token lifetime -->
    refreshThreshold="5m"      <!-- Refresh when 5 min remaining -->
    maxLifetime="60m"          <!-- Absolute maximum lifetime -->
/>
```

### Refresh Logic

```java
public boolean shouldRefreshToken() {
    long currentTime = System.currentTimeMillis();
    long timeRemaining = expirationInMilliseconds - currentTime;
    long thresholdInMillis = refreshThresholdInMinutes * MILLIS_PER_MINUTE;
    
    // Refresh if within threshold and not exceeded max lifetime
    return timeRemaining <= thresholdInMillis && 
           currentTime < maxLifetimeInMilliseconds;
}
```

### Refresh Flow

```mermaid
flowchart TD
    Start([Request with LTPA Cookie]) --> ValidateToken[Validate Token]
    ValidateToken --> CheckExpiry{Token<br/>Expired?}
    
    CheckExpiry -->|Yes| Reject[Reject - Re-authenticate]
    CheckExpiry -->|No| CheckThreshold{Time Remaining ≤<br/>Refresh Threshold?}
    
    CheckThreshold -->|No| UseExisting[Use Existing Token]
    CheckThreshold -->|Yes| CheckMaxLife{Current Time <<br/>Max Lifetime?}
    
    CheckMaxLife -->|No| Reject
    CheckMaxLife -->|Yes| CreateNew[Create New Token]
    
    CreateNew --> ResetExp[Reset Expiration]
    ResetExp --> PreserveMaxLife[Preserve Max Lifetime]
    PreserveMaxLife --> UpdateCookie[Update LTPA Cookie]
    UpdateCookie --> GrantAccess[Grant Access]
    
    UseExisting --> GrantAccess
    GrantAccess --> End([Success])
    Reject --> End
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style CreateNew fill:#fff4e1
    style UpdateCookie fill:#fff4e1
    style Reject fill:#ffe1e1
```

### Key Features

- **Transparent**: Refresh happens automatically without user interaction
- **Threshold-Based**: Configurable time before expiration to trigger refresh
- **Max Lifetime**: Prevents indefinite token refresh
- **Cookie Update**: New token automatically set in response cookie
- **SSO Preservation**: Maintains single sign-on across servers

### Implementation

**Location**: `com.ibm.ws.webcontainer.security/src/com/ibm/ws/webcontainer/security/internal/SSOAuthenticator.java`

```java
private boolean shouldUpdateSSOCookie(HttpServletRequest req, Subject subject) {
    // Get original token from request cookie
    byte[] originalTokenBytes = getOriginalTokenBytes(req);
    
    // Get new token from authenticated subject
    byte[] newTokenBytes = ssoCookieHelper.getDefaultSSOTokenFromSubject(subject);
    
    // Check if tokens are different (token was refreshed)
    boolean tokenRefreshed = areTokensDifferent(originalTokenBytes, newTokenBytes);
    
    return tokenRefreshed;
}
```

---

## OAuth/OIDC Token Refresh

### Mechanism

OAuth/OIDC uses a **separate refresh_token** to obtain new access tokens and ID tokens.

### Configuration

```xml
<oauthProvider id="OAuthConfigSample">
    <grantType>authorization_code</grantType>
    <grantType>refresh_token</grantType>
    <accessTokenLifetime>3600</accessTokenLifetime>
    <authorizationGrantLifetime>604800</authorizationGrantLifetime>
</oauthProvider>
```

### Refresh Token Structure

```json
{
  "access_token": "qOuZdH6Anmxclul5d71AXoDbFVmRG2dPnHn9moaw",
  "token_type": "bearer",
  "expires_in": 3599,
  "scope": "openid profile",
  "refresh_token": "QGCYpfziPZY2saAagbsf5jxbMucqcF3743euknBxzkUlof7uSv",
  "id_token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

### Refresh Flow

```mermaid
flowchart TD
    Start([Client Has Refresh Token]) --> CheckExpiry{Access Token<br/>Expired?}
    
    CheckExpiry -->|No| UseExisting[Use Existing Access Token]
    CheckExpiry -->|Yes| BuildRequest[Build Token Request]
    
    BuildRequest --> SetGrantType[grant_type=refresh_token]
    SetGrantType --> SetRefreshToken[refresh_token=...]
    SetRefreshToken --> SetClientCreds[Add Client Credentials]
    
    SetClientCreds --> SendRequest[POST to Token Endpoint]
    SendRequest --> ValidateRequest{Request<br/>Valid?}
    
    ValidateRequest -->|No| Error[Return Error]
    ValidateRequest -->|Yes| ValidateRefreshToken{Refresh Token<br/>Valid?}
    
    ValidateRefreshToken -->|No| Error
    ValidateRefreshToken -->|Yes| CheckClient{Client ID<br/>Matches?}
    
    CheckClient -->|No| Error
    CheckClient -->|Yes| CheckLifetime{Within Max<br/>Lifetime?}
    
    CheckLifetime -->|No| Error
    CheckLifetime -->|Yes| CreateNewTokens[Create New Tokens]
    
    CreateNewTokens --> NewAccessToken[New Access Token]
    NewAccessToken --> NewRefreshToken[New Refresh Token]
    NewRefreshToken --> OptionalIDToken[Optional: New ID Token]
    
    OptionalIDToken --> ReturnTokens[Return Token Response]
    ReturnTokens --> Success[Success]
    
    UseExisting --> Success
    Success --> End([End])
    Error --> End
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style Success fill:#e1f5e1
    style CreateNewTokens fill:#fff4e1
    style Error fill:#ffe1e1
```

### Refresh Request

```http
POST /oauth2/endpoint/OAuthConfigSample/token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic Y2xpZW50MDE6c2VjcmV0

grant_type=refresh_token&
refresh_token=QGCYpfziPZY2saAagbsf5jxbMucqcF3743euknBxzkUlof7uSv&
scope=openid profile
```

### Refresh Response

```json
{
  "access_token": "EmItdyfKwjN03hW1URF67XrC9LuFDGqXwMoaudwN",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "openid profile",
  "refresh_token": "TFEoA9fOhQ3GFjohJ1QksUKlmE7mei0iXlUJKsfrl1FRnzjPdg"
}
```

### Implementation

**Location**: `com.ibm.oauth.core.internal.oauth20.granttype.impl.OAuth20GrantTypeHandlerRefreshImpl.java`

```java
public List<OAuth20Token> buildTokensGrantType(
        AttributeList attributeList,
        OAuth20TokenFactory tokenFactory,
        List<OAuth20Token> tokens) {
    
    OAuth20Token refresh = tokens.get(0); // Original refresh token
    
    // Validate client ID matches
    if (!clientId.equals(refresh.getClientId())) {
        throw new OAuth20RefreshTokenInvalidClientException(
            refresh.getTokenString(), clientId);
    }
    
    // Create new access token
    OAuth20Token access = tokenFactory.createAccessToken(accessTokenMap);
    
    // Create new refresh token
    OAuth20Token newRefresh = tokenFactory.createRefreshToken(refreshTokenMap);
    
    // Link access token to refresh token
    ((OAuth20TokenImpl) access).setRefreshTokenKey(newRefresh.getId());
    
    return Arrays.asList(access, newRefresh);
}
```

### Key Features

- **Explicit Refresh**: Client must explicitly request token refresh
- **Separate Token**: Refresh token is distinct from access token
- **Long-Lived**: Refresh tokens typically have longer lifetime
- **Revocable**: Can be revoked independently
- **Grant Type**: Uses `grant_type=refresh_token`
- **Client Authentication**: Requires client credentials

---

## JWT Token Refresh

### Mechanism

JWT tokens **do not support automatic refresh**. They must be re-issued through authentication.

### Why No Refresh?

1. **Stateless**: JWTs are self-contained and stateless
2. **Immutable**: Cannot be modified after signing
3. **Expiration**: Controlled by `exp` claim
4. **Re-authentication**: New token requires new authentication

### Token Structure

```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "iss": "https://server.example.com",
    "sub": "user@example.com",
    "aud": "client01",
    "exp": 1460058764,
    "iat": 1460058759,
    "scope": "openid profile"
  },
  "signature": "..."
}
```

### Handling Expiration

```mermaid
flowchart TD
    Start([Request with JWT]) --> ValidateToken[Validate JWT Signature]
    ValidateToken --> SigValid{Signature<br/>Valid?}
    
    SigValid -->|No| Reject[Reject - Invalid Token]
    SigValid -->|Yes| CheckExpiry[Check exp Claim]
    
    CheckExpiry --> Expired{Current Time ><br/>exp?}
    Expired -->|Yes| RejectExpired[Reject - Token Expired]
    Expired -->|No| CheckNotBefore[Check nbf Claim]
    
    CheckNotBefore --> NotYetValid{Current Time <<br/>nbf?}
    NotYetValid -->|Yes| RejectNotYet[Reject - Not Yet Valid]
    NotYetValid -->|No| GrantAccess[Grant Access]
    
    GrantAccess --> End([Success])
    Reject --> End
    RejectExpired --> End
    RejectNotYet --> End
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style GrantAccess fill:#e1f5e1
    style Reject fill:#ffe1e1
    style RejectExpired fill:#ffe1e1
    style RejectNotYet fill:#ffe1e1
```

### Alternatives to Refresh

#### 1. Short-Lived JWT + Refresh Token

```xml
<openidConnectProvider id="OP">
    <jwtBuilder 
        id="myBuilder"
        expiresInSeconds="300"  <!-- 5 minutes -->
    />
    <grantType>authorization_code</grantType>
    <grantType>refresh_token</grantType>
</openidConnectProvider>
```

#### 2. Sliding Window Pattern

```java
// Issue new JWT if current one is close to expiration
if (jwt.getExpirationTime() - currentTime < REFRESH_WINDOW) {
    return issueNewJWT(user);
}
return jwt;
```

#### 3. Silent Re-authentication

```javascript
// Client-side: Use hidden iframe to re-authenticate
function refreshJWT() {
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    iframe.src = '/oauth/authorize?prompt=none&...';
    document.body.appendChild(iframe);
}
```

### Key Features

- **No Refresh**: JWTs cannot be refreshed
- **Stateless**: No server-side session required
- **Self-Contained**: All info in the token
- **Expiration**: Controlled by `exp` claim
- **Re-issue**: Requires new authentication

---

## SPNEGO Token Refresh

### Mechanism

SPNEGO tokens **do not support refresh**. They rely on Kerberos ticket lifetime.

### Token Lifecycle

```mermaid
flowchart TD
    Start([User Login]) --> KerberosAuth[Authenticate with KDC]
    KerberosAuth --> GetTGT[Receive TGT]
    GetTGT --> RequestService[Request Service Ticket]
    RequestService --> GetServiceTicket[Receive Service Ticket]
    
    GetServiceTicket --> CreateSPNEGO[Create SPNEGO Token]
    CreateSPNEGO --> SendToServer[Send to Server]
    SendToServer --> ValidateToken[Server Validates Token]
    
    ValidateToken --> CheckExpiry{Ticket<br/>Expired?}
    CheckExpiry -->|Yes| ReAuth[Re-authenticate with KDC]
    CheckExpiry -->|No| GrantAccess[Grant Access]
    
    ReAuth --> GetTGT
    GrantAccess --> NextRequest{Next<br/>Request?}
    
    NextRequest -->|Yes| CheckTicket{Ticket Still<br/>Valid?}
    NextRequest -->|No| End([End])
    
    CheckTicket -->|Yes| SendToServer
    CheckTicket -->|No| ReAuth
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style GrantAccess fill:#e1f5e1
    style ReAuth fill:#fff4e1
```

### Kerberos Ticket Lifetime

```ini
[libdefaults]
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    renewable = true
```

### Handling Expiration

When SPNEGO token expires:

1. **Client Re-authenticates**: Obtains new Kerberos ticket from KDC
2. **New Token Created**: Client creates new SPNEGO token
3. **Transparent to User**: If Kerberos TGT is still valid
4. **User Prompted**: If TGT expired, user must re-enter credentials

### Test Token Refresh

**Location**: `com.ibm.ws.security.spnego_fat/fat/src/com/ibm/ws/security/spnego/fat/ApacheKDCCommonTest.java`

```java
/**
 * Determines whether the common SPNEGO token was created too far in the past 
 * to be usable in upcoming tests.
 */
private static boolean shouldCommonTokenBeRefreshed() {
    long currentTime = System.currentTimeMillis();
    long tokenAge = (currentTime - COMMON_TOKEN_CREATION_DATE) / 1000;
    
    if (tokenAge > TOKEN_REFRESH_LIFETIME_SECONDS) {
        Log.info(c, "shouldCommonTokenBeRefreshed", 
                "SPNEGO token lifetime exceeded; recommend new token");
        return true;
    }
    return false;
}
```

### Key Features

- **No Server Refresh**: Server cannot refresh SPNEGO tokens
- **Kerberos-Based**: Lifetime controlled by Kerberos tickets
- **Client Responsibility**: Client must obtain new tickets
- **Transparent**: Can be transparent if TGT is renewable
- **Re-authentication**: May require user credentials if TGT expired

---

## Jakarta Security Token Refresh

### Mechanism

Jakarta Security 3.0 supports **automatic token refresh** for OpenID Connect tokens.

### Configuration

```java
@OpenIdAuthenticationMechanismDefinition(
    providerURI = "https://provider.example.com",
    clientId = "client01",
    clientSecret = "secret",
    redirectURI = "${baseURL}/callback",
    tokenAutoRefresh = true,  // Enable automatic refresh
    tokenMinValidity = 10     // Refresh if < 10 seconds remaining
)
```

### Refresh Logic

**Location**: `io.openliberty.security.oidcclientcore.internal/src/io/openliberty/security/oidcclientcore/client/Client.java`

```java
public ProviderAuthenticationResult handleTokensForAuthenticatedRequest(
        HttpServletRequest request,
        OidcClientConfig oidcClientConfig,
        boolean isAccessTokenExpired,
        boolean isIdTokenExpired,
        String refreshTokenString) {
    
    TokenRefresher tokenRefresher = new TokenRefresher(
        request, oidcClientConfig, 
        isAccessTokenExpired, isIdTokenExpired, 
        refreshTokenString
    );
    
    if (oidcClientConfig.isTokenAutoRefresh()) {
        // No refresh_token available - initiate logout
        if (refreshTokenString == null) {
            return initiateLogout(request, oidcClientConfig);
        }
        
        // Refresh the tokens
        ProviderAuthenticationResult providerAuthResult = 
            tokenRefresher.refreshToken();
        
        if (AuthResult.SUCCESS.equals(providerAuthResult.getStatus())) {
            return providerAuthResult;
        }
    }
    
    return handleExpiredTokens(request, oidcClientConfig);
}
```

### Refresh Flow

```mermaid
flowchart TD
    Start([Request to Protected Resource]) --> CheckTokens{Tokens<br/>Expired?}
    
    CheckTokens -->|No| GrantAccess[Grant Access]
    CheckTokens -->|Yes| CheckAutoRefresh{tokenAutoRefresh<br/>Enabled?}
    
    CheckAutoRefresh -->|No| CheckNotify{notifyProvider<br/>Enabled?}
    CheckAutoRefresh -->|Yes| HasRefreshToken{Has refresh_token?}
    
    HasRefreshToken -->|No| InitiateLogout[Initiate Logout]
    HasRefreshToken -->|Yes| SendRefreshRequest[Send Refresh Request]
    
    SendRefreshRequest --> RefreshSuccess{Refresh<br/>Success?}
    RefreshSuccess -->|No| CheckNotify
    RefreshSuccess -->|Yes| UpdateTokens[Update Tokens in Session]
    
    UpdateTokens --> GrantAccess
    
    CheckNotify -->|Yes| InitiateLogout
    CheckNotify -->|No| ReAuthenticate[Re-authenticate User]
    
    ReAuthenticate --> GrantAccess
    GrantAccess --> End([Success])
    InitiateLogout --> End
    
    style Start fill:#e1f5e1
    style End fill:#e1f5e1
    style GrantAccess fill:#e1f5e1
    style UpdateTokens fill:#fff4e1
    style InitiateLogout fill:#ffe1e1
```

### Test Scenarios

**Location**: `io.openliberty.security.jakartasec.3.0.internal_fat.refresh/fat/src/io/openliberty/security/jakartasec/fat/refresh/tests/BasicRefreshTests.java`

```java
/**
 * Test that tokens are refreshed when tokenAutoRefresh=true, 
 * provider includes refresh_token, and tokens are expired.
 */
@Test
public void testTokensRefreshedWhenExpired() throws Exception {
    // Initial authentication
    Page response1 = invokeAppAndAuthenticate();
    
    // Wait for tokens to expire
    Thread.sleep(TOKEN_EXPIRATION_TIME);
    
    // Access app again - should trigger refresh
    Page response2 = invokeAppGetToAppWithRefreshedToken(webClient, url);
    
    // Verify tokens were refreshed
    if (tokensAreDifferent(response1, response2, 
                          providerAllowsRefresh, TokenWasRefreshed)) {
        Log.info(thisClass, testName, "Tokens were refreshed");
    } else {
        fail("Tokens were NOT refreshed");
    }
}
```

### Key Features

- **Automatic**: Refresh happens automatically when configured
- **Configurable**: `tokenAutoRefresh` and `tokenMinValidity` settings
- **Refresh Token**: Uses OAuth refresh_token
- **Fallback**: Can re-authenticate if refresh fails
- **Logout Option**: Can logout if refresh not possible

---

## Best Practices

### LTPA Token Refresh

✅ **Do**:
- Set `refreshThreshold` to 1/3 of `expiration`
- Configure `maxLifetime` to 2-4x `expiration`
- Enable LTPA cookies for SSO
- Monitor token refresh rates

❌ **Don't**:
- Set `refreshThreshold` too small (< 1 minute)
- Disable `maxLifetime` in production
- Use very long expiration times (> 30 minutes)

### OAuth/OIDC Token Refresh

✅ **Do**:
- Include `refresh_token` in grant types
- Use short-lived access tokens (5-15 minutes)
- Use long-lived refresh tokens (days/weeks)
- Implement refresh token rotation
- Revoke refresh tokens on logout

❌ **Don't**:
- Store refresh tokens in browser localStorage
- Use refresh tokens without client authentication
- Allow unlimited refresh token lifetime
- Ignore refresh token revocation

### JWT Token Refresh

✅ **Do**:
- Use short expiration times (5-15 minutes)
- Combine with refresh tokens for long sessions
- Implement sliding window for re-issue
- Use `exp` and `nbf` claims properly

❌ **Don't**:
- Try to modify JWT after signing
- Use very long expiration times
- Store sensitive data in JWT payload
- Ignore token expiration

### SPNEGO Token Refresh

✅ **Do**:
- Configure appropriate Kerberos ticket lifetimes
- Enable ticket renewal
- Implement graceful re-authentication
- Monitor ticket expiration

❌ **Don't**:
- Expect server-side token refresh
- Use very short ticket lifetimes
- Ignore Kerberos configuration
- Disable ticket renewal

### Jakarta Security Token Refresh

✅ **Do**:
- Enable `tokenAutoRefresh` for better UX
- Set appropriate `tokenMinValidity`
- Handle refresh failures gracefully
- Configure `notifyProvider` appropriately

❌ **Don't**:
- Rely solely on automatic refresh
- Ignore refresh token absence
- Set `tokenMinValidity` too high
- Disable logout on refresh failure

---

## Summary

| Token Type | Refresh Method | Configuration | Use Case |
|------------|---------------|---------------|----------|
| **LTPA** | Automatic server-side | `refreshThreshold`, `maxLifetime` | SSO across Liberty servers |
| **OAuth/OIDC** | Explicit with refresh_token | `grant_type=refresh_token` | API access, mobile apps |
| **JWT** | Re-issue only | `exp` claim | Stateless authentication |
| **SPNEGO** | Client re-authentication | Kerberos ticket lifetime | Windows domain SSO |
| **Jakarta Security** | Automatic with refresh_token | `tokenAutoRefresh` | Modern web applications |

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-15  
**Author**: Bob (AI Assistant)  
**Location**: `/Users/utle/libertyGit/open-liberty/dev/bob-docs/Liberty_Token_Refresh_Comparison.md`