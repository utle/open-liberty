# LTPA High Security Timeout Configuration Guide

## Executive Summary

This document provides comprehensive recommendations for configuring LTPA token expiration and HTTP session timeouts in high-security environments. It addresses the critical relationship between LTPA token lifetime and session management to ensure secure, consistent authentication behavior.

**Target Audience**: Security Architects, System Administrators, DevOps Engineers  
**Security Level**: High Security / Enterprise  
**Last Updated**: 2026-04-15

---

## Table of Contents

1. [Understanding LTPA and Session Timeouts](#understanding-ltpa-and-session-timeouts)
2. [High Security Configuration Principles](#high-security-configuration-principles)
3. [Recommended Timeout Values](#recommended-timeout-values)
4. [Configuration Examples](#configuration-examples)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)

---

## Understanding LTPA and Session Timeouts

### LTPA Token Lifecycle

LTPA (Lightweight Third-Party Authentication) tokens have three key timing parameters:

```
┌─────────────────────────────────────────────────────────────┐
│                    LTPA Token Timeline                       │
└─────────────────────────────────────────────────────────────┘

Creation                    Refresh Point              Expiration
    │                            │                          │
    │◄────── expiration ────────►│                          │
    │                            │                          │
    │◄────────────── maxLifetime ──────────────────────────►│
    │                            │                          │
    │                            │◄─ refreshThreshold ─────►│
    │                            │                          │
    ▼                            ▼                          ▼
  Token                    Token can be              Token invalid
 Created                    refreshed                (must re-auth)
```

### HTTP Session vs LTPA Token

**Critical Relationship**:
```
HTTP Session Timeout ≤ LTPA Token Expiration

Why? If session expires before token, user loses session state
     but still has valid authentication token (inconsistent state)
```

---

## High Security Configuration Principles

### 1. Minimize Token Lifetime

**Principle**: Shorter token lifetimes reduce the window of opportunity for token theft and replay attacks.

**Recommendation**: 
- **LTPA Expiration**: 15-30 minutes (high security)
- **Session Timeout**: Equal to or less than LTPA expiration

### 2. Enforce Token Refresh

**Principle**: Regular token refresh ensures continuous validation and allows for policy changes.

**Recommendation**:
- **Refresh Threshold**: 5-10 minutes before expiration
- **Max Lifetime**: 2-4 hours (absolute maximum)

### 3. Coordinate with Session Management

**Principle**: Session and token timeouts must be synchronized to prevent authentication/session mismatches.

**Critical Rule**:
```
sessionTimeout ≤ ltpaExpiration ≤ ltpaMaxLifetime
```

---

## Recommended Timeout Values

### High Security Environment (Recommended)

```xml
<ltpa 
    expiration="15m"           <!-- Token expires after 15 minutes -->
    refreshThreshold="5m"      <!-- Refresh 5 minutes before expiry -->
    maxLifetime="60m"          <!-- Absolute max: 1 hour -->
/>

<httpSession 
    invalidateOnUnauthorizedSessionRequestException="true"
    invalidationTimeout="15m"  <!-- Match LTPA expiration -->
/>
```

**Rationale**:
- ✅ 15-minute expiration limits exposure window
- ✅ 5-minute refresh threshold provides smooth user experience
- ✅ 1-hour max lifetime prevents indefinite token refresh
- ✅ Session timeout matches token expiration (no mismatch)

### Balanced Security Environment

```xml
<ltpa 
    expiration="30m"           <!-- Token expires after 30 minutes -->
    refreshThreshold="10m"     <!-- Refresh 10 minutes before expiry -->
    maxLifetime="120m"         <!-- Absolute max: 2 hours -->
/>

<httpSession 
    invalidateOnUnauthorizedSessionRequestException="true"
    invalidationTimeout="30m"  <!-- Match LTPA expiration -->
/>
```

**Rationale**:
- ✅ 30-minute expiration balances security and usability
- ✅ 10-minute refresh threshold reduces refresh frequency
- ✅ 2-hour max lifetime for longer work sessions
- ✅ Session timeout matches token expiration

### Maximum Security Environment

```xml
<ltpa 
    expiration="10m"           <!-- Token expires after 10 minutes -->
    refreshThreshold="3m"      <!-- Refresh 3 minutes before expiry -->
    maxLifetime="30m"          <!-- Absolute max: 30 minutes -->
    replayProtectionEnabled="true"
    clientBindingEnabled="true"
/>

<httpSession 
    invalidateOnUnauthorizedSessionRequestException="true"
    invalidationTimeout="10m"  <!-- Match LTPA expiration -->
    cookieSecure="true"
    cookieHttpOnly="true"
    cookieSameSite="Strict"
/>
```

**Rationale**:
- ✅ 10-minute expiration minimizes attack window
- ✅ 30-minute max lifetime forces periodic re-authentication
- ✅ Replay protection prevents token reuse
- ✅ Client binding prevents token theft
- ✅ Secure cookie settings enhance protection

---

## Configuration Examples

### Example 1: Financial Services (Maximum Security)

```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
        <feature>servlet-5.0</feature>
    </featureManager>
    
    <!-- LTPA Configuration -->
    <ltpa 
        keysFileName="${server.output.dir}/resources/security/ltpa.keys"
        keysPassword="{xor}Lz4sLCgwLTs="
        expiration="10m"
        refreshThreshold="3m"
        maxLifetime="30m"
        replayProtectionEnabled="true"
        clientBindingEnabled="true"
        clientBindingStrategy="fingerprint"
    />
    
    <!-- HTTP Session Configuration -->
    <httpSession 
        invalidateOnUnauthorizedSessionRequestException="true"
        invalidationTimeout="10m"
        cookieSecure="true"
        cookieHttpOnly="true"
        cookieSameSite="Strict"
        securityIntegrationEnabled="true"
    />
    
    <!-- Web Application Security -->
    <webAppSecurity 
        ssoRequiresSSL="true"
        httpOnlyCookies="true"
        ssoUseDomainFromURL="false"
    />
</server>
```

**Key Features**:
- 10-minute token and session timeout
- Replay protection enabled
- Client binding with fingerprint strategy
- Secure cookie configuration
- SSL required for SSO

### Example 2: Enterprise Application (High Security)

```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
        <feature>servlet-5.0</feature>
    </featureManager>
    
    <!-- LTPA Configuration -->
    <ltpa 
        keysFileName="${server.output.dir}/resources/security/ltpa.keys"
        keysPassword="{xor}Lz4sLCgwLTs="
        expiration="15m"
        refreshThreshold="5m"
        maxLifetime="60m"
        replayProtectionEnabled="true"
    />
    
    <!-- HTTP Session Configuration -->
    <httpSession 
        invalidateOnUnauthorizedSessionRequestException="true"
        invalidationTimeout="15m"
        cookieSecure="true"
        cookieHttpOnly="true"
        cookieSameSite="Lax"
    />
    
    <!-- Web Application Security -->
    <webAppSecurity 
        ssoRequiresSSL="true"
        httpOnlyCookies="true"
    />
</server>
```

**Key Features**:
- 15-minute token and session timeout
- 1-hour maximum lifetime
- Replay protection enabled
- Balanced security and usability

### Example 3: Internal Application (Balanced Security)

```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
        <feature>servlet-5.0</feature>
    </featureManager>
    
    <!-- LTPA Configuration -->
    <ltpa 
        keysFileName="${server.output.dir}/resources/security/ltpa.keys"
        keysPassword="{xor}Lz4sLCgwLTs="
        expiration="30m"
        refreshThreshold="10m"
        maxLifetime="120m"
    />
    
    <!-- HTTP Session Configuration -->
    <httpSession 
        invalidateOnUnauthorizedSessionRequestException="true"
        invalidationTimeout="30m"
        cookieHttpOnly="true"
    />
</server>
```

**Key Features**:
- 30-minute token and session timeout
- 2-hour maximum lifetime
- Standard security features

---

## Security Considerations

### 1. Session Timeout Must Not Exceed LTPA Expiration

**Problem**: If session timeout > LTPA expiration:
```
Time 0:  User logs in (token + session created)
Time 15: LTPA token expires
Time 20: Session still valid, but token invalid
         → User has session but no authentication
         → Inconsistent security state
```

**Solution**: Always set `sessionTimeout ≤ ltpaExpiration`

### 2. Refresh Threshold Calculation

**Formula**:
```
refreshThreshold = expiration - (buffer time)

Recommended buffer: 30-50% of expiration time
```

**Examples**:
- Expiration 10m → Refresh threshold 3-5m
- Expiration 15m → Refresh threshold 5-7m
- Expiration 30m → Refresh threshold 10-15m

### 3. Maximum Lifetime Enforcement

**Purpose**: Prevent indefinite token refresh

**Recommendation**:
```
maxLifetime = 2-4 × expiration

Examples:
- Expiration 10m → Max lifetime 30-40m
- Expiration 15m → Max lifetime 60m
- Expiration 30m → Max lifetime 120m
```

### 4. Token Refresh Behavior

**How Token Refresh Works**:
```
1. User makes request with token
2. Server checks: (currentTime + refreshThreshold) > expirationTime?
3. If yes: Create new token with extended expiration
4. If no: Continue with existing token
5. Check: (currentTime - creationTime) > maxLifetime?
6. If yes: Force re-authentication (no refresh allowed)
```

### 5. Session Invalidation on Token Expiry

**Configuration**:
```xml
<httpSession 
    invalidateOnUnauthorizedSessionRequestException="true"
/>
```

**Behavior**:
- When LTPA token expires and cannot be refreshed
- HTTP session is automatically invalidated
- User must re-authenticate
- Prevents orphaned sessions

---

## Advanced Security Features

### Combining Multiple Security Features

**Maximum Security Configuration**:
```xml
<ltpa 
    expiration="10m"
    refreshThreshold="3m"
    maxLifetime="30m"
    replayProtectionEnabled="true"
    clientBindingEnabled="true"
    clientBindingStrategy="fingerprint"
    sessionTrackingEnabled="true"
    maxSessionsPerUser="3"
/>
```

**Security Layers**:
1. **Short Expiration (10m)**: Limits exposure window
2. **Replay Protection**: Prevents token reuse
3. **Client Binding**: Prevents token theft
4. **Session Tracking**: Enables immediate revocation
5. **Concurrent Session Limits**: Prevents session hijacking

### Session Tracking with High Security

When using session tracking feature:
```xml
<ltpa 
    expiration="15m"
    maxLifetime="60m"
    sessionTrackingEnabled="true"
    maxSessionsPerUser="5"
/>

<httpSession 
    invalidationTimeout="15m"
/>
```

**Benefits**:
- Immediate token revocation on logout
- Limit concurrent sessions per user
- Track active sessions
- Enhanced audit trail

---

## Troubleshooting

### Issue 1: Users Logged Out Too Frequently

**Symptoms**:
- Users complain about frequent re-authentication
- Session expires during active use

**Diagnosis**:
```
Check: Is expiration too short?
Check: Is refreshThreshold too small?
Check: Is maxLifetime too restrictive?
```

**Solution**:
```xml
<!-- Increase expiration and adjust thresholds -->
<ltpa 
    expiration="30m"           <!-- Increased from 15m -->
    refreshThreshold="10m"     <!-- Increased from 5m -->
    maxLifetime="120m"         <!-- Increased from 60m -->
/>
```

### Issue 2: Session Valid But Authentication Failed

**Symptoms**:
- HTTP session exists but authentication fails
- "Unauthorized" errors with valid session

**Diagnosis**:
```
Check: sessionTimeout > ltpaExpiration?
```

**Solution**:
```xml
<!-- Ensure session timeout ≤ LTPA expiration -->
<ltpa expiration="15m" />
<httpSession invalidationTimeout="15m" />  <!-- Match or less -->
```

### Issue 3: Token Not Refreshing

**Symptoms**:
- Token expires even during active use
- No automatic refresh occurring

**Diagnosis**:
```
Check: Is refreshThreshold configured?
Check: Is refreshThreshold too small?
Check: Has maxLifetime been reached?
```

**Solution**:
```xml
<ltpa 
    expiration="30m"
    refreshThreshold="10m"     <!-- Must be > 0 -->
    maxLifetime="120m"         <!-- Must be > expiration -->
/>
```

### Issue 4: Tokens Refreshing Indefinitely

**Symptoms**:
- Users never forced to re-authenticate
- Tokens refresh beyond expected lifetime

**Diagnosis**:
```
Check: Is maxLifetime configured?
Check: Is maxLifetime too large?
```

**Solution**:
```xml
<ltpa 
    expiration="30m"
    maxLifetime="120m"         <!-- Set reasonable limit -->
/>
```

---

## Monitoring and Validation

### Verify Configuration

**Check LTPA Settings**:
```bash
# View server.xml configuration
cat ${WLP_HOME}/usr/servers/myServer/server.xml | grep -A 5 "<ltpa"

# Check messages.log for LTPA initialization
grep "CWWKS4105I" ${WLP_HOME}/usr/servers/myServer/logs/messages.log
```

**Expected Output**:
```
CWWKS4105I: LTPA configuration is ready after X seconds.
```

### Monitor Token Refresh

**Enable Trace**:
```xml
<logging traceSpecification="com.ibm.ws.security.token.ltpa.*=all" />
```

**Look For**:
```
Token refresh triggered: sessionId=xxx, userId=yyy
Token refresh successful: newExpiration=zzz
Token refresh denied: maxLifetime exceeded
```

### Session Timeout Validation

**Test Scenario**:
```
1. Login to application
2. Note token expiration time
3. Wait until (expiration - refreshThreshold)
4. Make request → Should get refreshed token
5. Wait until maxLifetime
6. Make request → Should require re-authentication
```

---

## Best Practices Summary

### ✅ DO

1. **Set session timeout ≤ LTPA expiration**
   ```xml
   <ltpa expiration="15m" />
   <httpSession invalidationTimeout="15m" />
   ```

2. **Configure refresh threshold (30-50% of expiration)**
   ```xml
   <ltpa expiration="30m" refreshThreshold="10m" />
   ```

3. **Set reasonable maxLifetime (2-4× expiration)**
   ```xml
   <ltpa expiration="30m" maxLifetime="120m" />
   ```

4. **Enable session invalidation on auth failure**
   ```xml
   <httpSession invalidateOnUnauthorizedSessionRequestException="true" />
   ```

5. **Use secure cookie settings**
   ```xml
   <httpSession cookieSecure="true" cookieHttpOnly="true" />
   ```

### ❌ DON'T

1. **Don't set session timeout > LTPA expiration**
   ```xml
   <!-- WRONG -->
   <ltpa expiration="15m" />
   <httpSession invalidationTimeout="30m" />  <!-- Too long! -->
   ```

2. **Don't omit refreshThreshold**
   ```xml
   <!-- WRONG - No refresh will occur -->
   <ltpa expiration="30m" />  <!-- Missing refreshThreshold -->
   ```

3. **Don't set maxLifetime ≤ expiration**
   ```xml
   <!-- WRONG - Tokens can't refresh -->
   <ltpa expiration="30m" maxLifetime="30m" />
   ```

4. **Don't use very short timeouts without user warning**
   ```xml
   <!-- WRONG for user experience -->
   <ltpa expiration="5m" />  <!-- Too aggressive -->
   ```

---

## Quick Reference Table

| Security Level | Expiration | Refresh Threshold | Max Lifetime | Session Timeout |
|----------------|------------|-------------------|--------------|-----------------|
| **Maximum**    | 10m        | 3m                | 30m          | 10m             |
| **High**       | 15m        | 5m                | 60m          | 15m             |
| **Balanced**   | 30m        | 10m               | 120m         | 30m             |
| **Standard**   | 60m        | 20m               | 240m         | 60m             |

**Formula**:
```
refreshThreshold = expiration × 0.3 to 0.5
maxLifetime = expiration × 2 to 4
sessionTimeout = expiration (or less)
```

---

## Conclusion

For high-security LTPA configurations:

1. **Use short token expiration** (10-15 minutes)
2. **Configure appropriate refresh threshold** (30-50% of expiration)
3. **Set reasonable max lifetime** (2-4× expiration)
4. **Match session timeout to token expiration** (critical!)
5. **Enable additional security features** (replay protection, client binding)
6. **Use secure cookie settings**
7. **Monitor and validate** configuration

**Recommended High Security Configuration**:
```xml
<ltpa 
    expiration="15m"
    refreshThreshold="5m"
    maxLifetime="60m"
    replayProtectionEnabled="true"
/>

<httpSession 
    invalidateOnUnauthorizedSessionRequestException="true"
    invalidationTimeout="15m"
    cookieSecure="true"
    cookieHttpOnly="true"
/>
```

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-15  
**Author**: IBM Liberty Security Team  
**Status**: Production Ready