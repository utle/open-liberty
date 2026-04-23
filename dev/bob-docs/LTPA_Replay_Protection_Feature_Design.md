# LTPA Token Replay Protection Feature Design

## Executive Summary

This document specifies a new feature to add replay attack protection for LTPA tokens in IBM WebSphere Liberty, similar to the JTI-based protection currently available for JWT tokens. This addresses a critical security gap where LTPA tokens can be intercepted and reused by attackers.

**Feature ID**: `ltpaReplayProtection-1.0`  
**Target Release**: Liberty 26.0.0.x  
**Priority**: High (Security Enhancement)  
**Status**: Design Phase

---

## Table of Contents

1. [Problem Statement](#problem-statement)
2. [Current State Analysis](#current-state-analysis)
3. [Proposed Solution](#proposed-solution)
4. [Technical Design](#technical-design)
5. [Implementation Plan](#implementation-plan)
6. [Configuration](#configuration)
7. [Testing Strategy](#testing-strategy)
8. [Performance Considerations](#performance-considerations)
9. [Migration and Compatibility](#migration-and-compatibility)

---

## Problem Statement

### Current Vulnerability

LTPA tokens in Liberty currently lack built-in replay attack protection. Unlike JWT tokens which use JTI (JWT ID) claims cached on the server, LTPA tokens can be:

1. **Intercepted** via network sniffing (if HTTPS is not enforced)
2. **Stolen** via XSS attacks from browser cookies
3. **Reused** from any client/IP address until expiration
4. **Replayed** multiple times without detection

### Security Impact

- **High Risk**: Stolen LTPA tokens remain valid until expiration (default 120 minutes)
- **No Detection**: Server cannot distinguish legitimate use from replay attacks
- **Cross-Client Reuse**: Token stolen from one client works on any other client
- **Session Hijacking**: Attackers can impersonate users for extended periods

### Business Justification

- **Compliance**: Meet security standards (PCI-DSS, HIPAA, SOC 2)
- **Zero Trust**: Align with modern security architectures
- **Customer Demand**: Multiple customer requests for enhanced LTPA security
- **Competitive Parity**: JWT tokens already have this protection

---

## Current State Analysis

### LTPA Token Structure

```
LTPA Token Components:
┌─────────────────────────────────────────┐
│ Version (1 byte)                        │
├─────────────────────────────────────────┤
│ User Data (variable)                    │
│  - Username                             │
│  - Realm                                │
│  - Unique ID                            │
│  - Creation Time                        │
│  - Expiration Time                      │
├─────────────────────────────────────────┤
│ Digital Signature (RSA)                 │
└─────────────────────────────────────────┘
```

### Current Validation Flow

```java
// From LTPAToken2Factory.java
public Token validateTokenBytes(byte[] tokenBytes) {
    // 1. Decrypt token with shared key
    // 2. Verify RSA signature
    // 3. Check expiration time
    // 4. Extract user data
    // 5. Return validated token
    // ❌ NO REPLAY DETECTION
}
```

### Existing Protection Mechanisms

| Mechanism | Effectiveness | Limitations |
|-----------|---------------|-------------|
| Token Expiration | Medium | Long default lifetime (120 min) |
| HTTPS Enforcement | High | Not always configured |
| HttpOnly Cookies | Medium | Doesn't prevent all theft vectors |
| SameSite Cookies | Medium | Browser-dependent |
| Token Refresh | Low | Doesn't invalidate old tokens |

**Gap**: No mechanism to detect or prevent token reuse after theft.

---

## Proposed Solution

### High-Level Approach

Add a **Token ID (TID)** to LTPA tokens and implement server-side caching similar to JWT's JTI mechanism.

### Key Components

1. **Token ID Generation**: Unique identifier per LTPA token
2. **Token ID Cache**: Server-side cache tracking used tokens
3. **Validation Enhancement**: Check cache before accepting token
4. **Configuration Options**: Enable/disable, cache size, etc.
5. **Monitoring**: Metrics and alerts for replay attempts

### Design Principles

- **Backward Compatible**: Existing tokens continue to work
- **Opt-In**: Feature disabled by default for smooth migration
- **Performance**: Minimal overhead (<5ms per validation)
- **Scalability**: Support clustered environments
- **Configurable**: Flexible options for different use cases

---

## Technical Design

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    LTPA Token Flow                          │
└─────────────────────────────────────────────────────────────┘

Token Creation:
┌──────────┐    ┌──────────────┐    ┌──────────────┐
│  Client  │───▶│ LTPAToken2   │───▶│ Add Token ID │
│  Login   │    │ Constructor  │    │ (if enabled) │
└──────────┘    └──────────────┘    └──────────────┘
                                            │
                                            ▼
                                    ┌──────────────┐
                                    │ Encrypt &    │
                                    │ Sign Token   │
                                    └──────────────┘

Token Validation:
┌──────────┐    ┌──────────────┐    ┌──────────────┐
│  Client  │───▶│ Decrypt &    │───▶│ Verify       │
│  Request │    │ Verify Sig   │    │ Expiration   │
└──────────┘    └──────────────┘    └──────────────┘
                                            │
                                            ▼
                                    ┌──────────────┐
                                    │ Check TID    │◀──┐
                                    │ Cache        │   │
                                    └──────────────┘   │
                                            │          │
                                    ┌───────┴────────┐ │
                                    │                │ │
                            Found   │    Not Found   │ │
                                    │                │ │
                            ┌───────▼──┐      ┌─────▼──▼──┐
                            │ REJECT   │      │ Add to    │
                            │ (Replay) │      │ Cache     │
                            └──────────┘      └───────────┘
                                                     │
                                                     ▼
                                              ┌──────────┐
                                              │ ACCEPT   │
                                              └──────────┘
```

### Component Design

#### 1. LTPATokenIdCache

**Purpose**: Cache used token IDs to detect replays

**Implementation**:
```java
package com.ibm.ws.security.token.ltpa.internal;

import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.ws.security.common.structures.BoundedHashMap;

/**
 * Cache for tracking used LTPA token IDs to prevent replay attacks.
 * Similar to JtiNonceCache but optimized for LTPA tokens.
 */
public class LTPATokenIdCache {
    
    private static final TraceComponent tc = Tr.register(LTPATokenIdCache.class);
    
    /**
     * Cache structure: tokenId -> expirationTimeMillis
     */
    private final Map<String, Long> tokenCache;
    
    /**
     * Maximum number of entries (default: 100,000)
     */
    private final int maxEntries;
    
    /**
     * Cache cleanup interval (default: 5 minutes)
     */
    private final long cleanupIntervalMillis;
    
    /**
     * Executor for scheduled cleanup
     */
    private ScheduledExecutorService executorService;
    
    public LTPATokenIdCache(int maxEntries, long cleanupIntervalMillis) {
        this.maxEntries = maxEntries > 0 ? maxEntries : 100000;
        this.cleanupIntervalMillis = cleanupIntervalMillis > 0 ? 
            cleanupIntervalMillis : 5 * 60 * 1000;
        
        this.tokenCache = Collections.synchronizedMap(
            new BoundedHashMap(this.maxEntries)
        );
        
        scheduleCleanupTask();
    }
    
    /**
     * Check if token ID exists in cache (replay detection).
     * If not found, add it to cache.
     * 
     * @param tokenId The unique token identifier
     * @param expirationTimeMillis Token expiration time
     * @return true if token was already used (replay), false if first use
     */
    public boolean isTokenUsed(String tokenId, long expirationTimeMillis) {
        if (tokenId == null || tokenId.isEmpty()) {
            return false; // No token ID, skip replay check
        }
        
        long currentTime = System.currentTimeMillis();
        
        synchronized (tokenCache) {
            Long cachedExpiration = tokenCache.get(tokenId);
            
            if (cachedExpiration != null) {
                // Token ID found in cache
                if (cachedExpiration > currentTime) {
                    // Token still valid - REPLAY DETECTED
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "Replay attack detected for token ID: " + 
                            maskTokenId(tokenId));
                    }
                    return true;
                } else {
                    // Expired entry, remove it
                    tokenCache.remove(tokenId);
                }
            }
            
            // First use of this token - add to cache
            tokenCache.put(tokenId, expirationTimeMillis);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Token ID cached: " + maskTokenId(tokenId) + 
                    ", cache size: " + tokenCache.size());
            }
            
            return false;
        }
    }
    
    /**
     * Remove expired tokens from cache
     */
    protected void cleanupExpiredTokens() {
        long currentTime = System.currentTimeMillis();
        int removedCount = 0;
        
        synchronized (tokenCache) {
            Iterator<Map.Entry<String, Long>> iterator = 
                tokenCache.entrySet().iterator();
            
            while (iterator.hasNext()) {
                Map.Entry<String, Long> entry = iterator.next();
                if (entry.getValue() < currentTime) {
                    iterator.remove();
                    removedCount++;
                }
            }
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Cleanup removed " + removedCount + 
                " expired tokens, remaining: " + tokenCache.size());
        }
    }
    
    /**
     * Get current cache size
     */
    public int size() {
        return tokenCache.size();
    }
    
    /**
     * Clear all cached tokens (for testing)
     */
    public void clear() {
        tokenCache.clear();
    }
    
    /**
     * Mask token ID for logging (security)
     */
    private String maskTokenId(String tokenId) {
        if (tokenId == null || tokenId.length() < 8) {
            return "***";
        }
        return tokenId.substring(0, 4) + "..." + 
            tokenId.substring(tokenId.length() - 4);
    }
    
    /**
     * Schedule periodic cleanup task
     */
    private void scheduleCleanupTask() {
        executorService = SecurityOSGiUtils.getService(
            getClass(), ScheduledExecutorService.class
        );
        
        if (executorService != null) {
            executorService.scheduleWithFixedDelay(
                this::cleanupExpiredTokens,
                cleanupIntervalMillis,
                cleanupIntervalMillis,
                TimeUnit.MILLISECONDS
            );
        }
    }
}
```

#### 2. Enhanced LTPAToken2 with Token ID

**Modifications to LTPAToken2.java**:

```java
public class LTPAToken2 implements Token, Serializable {
    
    // Existing fields...
    private String tokenId; // NEW: Unique token identifier
    
    /**
     * Generate unique token ID
     */
    private String generateTokenId() {
        // Use secure random + timestamp + user info for uniqueness
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[16];
        random.nextBytes(randomBytes);
        
        String timestamp = String.valueOf(System.currentTimeMillis());
        String userInfo = userData.getUniqueId();
        
        // Combine and hash for compact ID
        String combined = Base64Coder.base64Encode(randomBytes) + 
            timestamp + userInfo;
        
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(combined.getBytes(StandardCharsets.UTF_8));
            return Base64Coder.base64Encode(hash);
        } catch (Exception e) {
            // Fallback to UUID
            return UUID.randomUUID().toString();
        }
    }
    
    /**
     * Constructor for creating new token (with token ID)
     */
    public LTPAToken2(String userUniqueId, 
                      long expirationInMinutes,
                      long maxLifetimeInMinutes,
                      long refreshThresholdInMinutes,
                      byte[] sharedKey,
                      LTPAPrivateKey privateKey,
                      LTPAPublicKey publicKey,
                      boolean enableReplayProtection) { // NEW parameter
        
        // Existing initialization...
        
        // Generate token ID if replay protection enabled
        if (enableReplayProtection) {
            this.tokenId = generateTokenId();
        }
        
        // Include token ID in user data
        if (tokenId != null) {
            userData.addAttribute(LTPAConstants.TOKEN_ID, tokenId);
        }
    }
    
    /**
     * Get token ID
     */
    public String getTokenId() {
        return tokenId;
    }
    
    /**
     * Extract token ID from user data (for validation)
     */
    private void extractTokenId() {
        if (userData != null) {
            this.tokenId = userData.getAttribute(LTPAConstants.TOKEN_ID);
        }
    }
}
```

#### 3. Enhanced LTPAToken2Factory with Replay Check

**Modifications to LTPAToken2Factory.java**:

```java
public class LTPAToken2Factory implements TokenFactory {
    
    // Existing fields...
    private boolean replayProtectionEnabled;
    private LTPATokenIdCache tokenIdCache;
    
    @Override
    public void initialize(Map tokenFactoryMap) {
        // Existing initialization...
        
        // NEW: Initialize replay protection
        replayProtectionEnabled = (Boolean) tokenFactoryMap.getOrDefault(
            LTPAConstants.REPLAY_PROTECTION_ENABLED, false
        );
        
        if (replayProtectionEnabled) {
            int cacheSize = (Integer) tokenFactoryMap.getOrDefault(
                LTPAConstants.REPLAY_CACHE_SIZE, 100000
            );
            long cleanupInterval = (Long) tokenFactoryMap.getOrDefault(
                LTPAConstants.REPLAY_CACHE_CLEANUP_INTERVAL, 5 * 60 * 1000L
            );
            
            tokenIdCache = new LTPATokenIdCache(cacheSize, cleanupInterval);
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "LTPA replay protection enabled, cache size: " + 
                    cacheSize);
            }
        }
    }
    
    @Override
    public Token createToken(Map tokenData) throws TokenCreationFailedException {
        String userUniqueId = getUniqueId(tokenData);
        
        // Pass replay protection flag to constructor
        return new LTPAToken2(userUniqueId, 
            expirationInMinutes, 
            maxLifetimeInMinutes, 
            refreshThresholdInMinutes, 
            primarySharedKey, 
            primaryPrivateKey, 
            primaryPublicKey,
            replayProtectionEnabled); // NEW parameter
    }
    
    @Override
    public Token validateTokenBytes(byte[] tokenBytes, String... removeAttributes) 
            throws InvalidTokenException, TokenExpiredException {
        
        // Existing validation...
        Token validatedToken = new LTPAToken2(tokenBytes, 
            primarySharedKey, 
            primaryPrivateKey, 
            primaryPublicKey, 
            expDiffAllowed, 
            expirationInMinutes, 
            maxLifetimeInMinutes, 
            refreshThresholdInMinutes, 
            removeAttributes);
        
        // NEW: Check for replay attack
        if (replayProtectionEnabled && validatedToken != null) {
            checkForReplayAttack(validatedToken);
        }
        
        // Existing refresh logic...
        return validatedToken;
    }
    
    /**
     * Check if token has been used before (replay detection)
     */
    private void checkForReplayAttack(Token token) 
            throws InvalidTokenException {
        
        if (!(token instanceof LTPAToken2)) {
            return;
        }
        
        LTPAToken2 ltpaToken = (LTPAToken2) token;
        String tokenId = ltpaToken.getTokenId();
        
        if (tokenId == null || tokenId.isEmpty()) {
            // Token created before replay protection was enabled
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Token has no ID, skipping replay check");
            }
            return;
        }
        
        long expirationMillis = ltpaToken.getExpiration();
        
        if (tokenIdCache.isTokenUsed(tokenId, expirationMillis)) {
            // REPLAY ATTACK DETECTED
            Tr.error(tc, "LTPA_TOKEN_REPLAY_DETECTED", tokenId);
            
            String errorMsg = Tr.formatMessage(tc, 
                "LTPA_TOKEN_REPLAY_DETECTED", 
                new Object[] { maskTokenId(tokenId) });
            
            throw new InvalidTokenException(errorMsg);
        }
    }
    
    private String maskTokenId(String tokenId) {
        if (tokenId == null || tokenId.length() < 8) {
            return "***";
        }
        return tokenId.substring(0, 4) + "..." + 
            tokenId.substring(tokenId.length() - 4);
    }
}
```

#### 4. Configuration Support

**New Constants in LTPAConstants.java**:

```java
public class LTPAConstants {
    // Existing constants...
    
    // NEW: Replay protection constants
    public static final String REPLAY_PROTECTION_ENABLED = "replayProtectionEnabled";
    public static final String REPLAY_CACHE_SIZE = "replayCacheSize";
    public static final String REPLAY_CACHE_CLEANUP_INTERVAL = "replayCacheCleanupInterval";
    public static final String TOKEN_ID = "tokenId";
}
```

**Enhanced metatype.xml**:

```xml
<metatype:MetaData>
    <OCD id="com.ibm.ws.security.token.ltpa" name="%ltpa.name" 
         description="%ltpa.desc">
        
        <!-- Existing attributes... -->
        
        <!-- NEW: Replay Protection Configuration -->
        <AD id="replayProtectionEnabled" 
            name="%replayProtectionEnabled.name"
            description="%replayProtectionEnabled.desc" 
            required="false" 
            type="Boolean" 
            default="false" />
        
        <AD id="replayCacheSize" 
            name="%replayCacheSize.name"
            description="%replayCacheSize.desc" 
            required="false" 
            type="Integer" 
            default="100000"
            min="1000"
            max="1000000" />
        
        <AD id="replayCacheCleanupInterval" 
            name="%replayCacheCleanupInterval.name"
            description="%replayCacheCleanupInterval.desc" 
            required="false" 
            type="String" 
            default="5m"
            ibm:type="duration(s)" />
        
    </OCD>
</metatype:MetaData>
```

**New Messages in LTPAMessages.nlsprops**:

```properties
# Replay Protection Messages
LTPA_TOKEN_REPLAY_DETECTED=CWWKS4150E: The LTPA token with ID [{0}] has already been used and cannot be accepted. This may indicate a replay attack.
LTPA_TOKEN_REPLAY_DETECTED.explanation=An LTPA token was presented that has already been validated and used. This typically indicates that the token was intercepted and is being replayed by an attacker.
LTPA_TOKEN_REPLAY_DETECTED.useraction=Ensure that HTTPS is properly configured and that tokens are not being intercepted. Review security logs for suspicious activity. Consider reducing the LTPA token expiration time.

LTPA_REPLAY_PROTECTION_ENABLED=CWWKS4151I: LTPA replay protection is enabled with cache size [{0}] and cleanup interval [{1}] milliseconds.
LTPA_REPLAY_PROTECTION_ENABLED.explanation=The LTPA token replay protection feature has been successfully enabled.
LTPA_REPLAY_PROTECTION_ENABLED.useraction=No action is required.

LTPA_REPLAY_CACHE_SIZE_WARNING=CWWKS4152W: The LTPA replay cache size [{0}] may be insufficient for the expected token volume. Consider increasing the cache size.
LTPA_REPLAY_CACHE_SIZE_WARNING.explanation=The replay protection cache may fill up quickly with the current configuration, potentially causing legitimate tokens to be rejected.
LTPA_REPLAY_CACHE_SIZE_WARNING.useraction=Monitor the cache size and increase the replayCacheSize configuration if needed.
```

---

## Configuration

### Server Configuration

**Basic Configuration (Replay Protection Enabled)**:
```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
        <feature>ltpaReplayProtection-1.0</feature>
    </featureManager>
    
    <ltpa 
        expiration="30m"
        replayProtectionEnabled="true" />
</server>
```

**Advanced Configuration**:
```xml
<ltpa 
    expiration="30m"
    replayProtectionEnabled="true"
    replayCacheSize="200000"
    replayCacheCleanupInterval="10m"
    keysFileName="ltpa.keys"
    keysPassword="{xor}Lz4sLCgwLTs=" />
```

**High-Volume Environment**:
```xml
<ltpa 
    expiration="15m"
    replayProtectionEnabled="true"
    replayCacheSize="500000"
    replayCacheCleanupInterval="5m" />
```

### Configuration Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `replayProtectionEnabled` | Boolean | false | Enable/disable replay protection |
| `replayCacheSize` | Integer | 100000 | Maximum number of token IDs to cache |
| `replayCacheCleanupInterval` | Duration | 5m | How often to remove expired entries |

### Migration Path

**Phase 1: Monitoring (Recommended)**
```xml
<!-- Enable but don't enforce - log only -->
<ltpa replayProtectionEnabled="true" 
      replayProtectionMode="monitor" />
```

**Phase 2: Enforcement**
```xml
<!-- Enforce replay protection -->
<ltpa replayProtectionEnabled="true" 
      replayProtectionMode="enforce" />
```

---

## Implementation Plan

### Phase 1: Core Implementation (Sprint 1-2)

**Week 1-2: Foundation**
- [ ] Create `LTPATokenIdCache` class
- [ ] Add token ID generation to `LTPAToken2`
- [ ] Update `LTPAToken2Factory` with replay check
- [ ] Add configuration support in `LTPAConfigurationImpl`
- [ ] Unit tests for cache operations

**Week 3-4: Integration**
- [ ] Integrate cache with token validation flow
- [ ] Add metatype configuration
- [ ] Add NLS messages
- [ ] Integration tests

### Phase 2: Testing & Refinement (Sprint 3)

**Week 5-6: Testing**
- [ ] FAT tests for replay detection
- [ ] Performance testing
- [ ] Cluster testing
- [ ] Security testing

**Week 7-8: Documentation**
- [ ] Feature documentation
- [ ] Configuration guide
- [ ] Migration guide
- [ ] Security best practices

### Phase 3: Release (Sprint 4)

**Week 9-10: Release Preparation**
- [ ] Code review
- [ ] Security review
- [ ] Performance validation
- [ ] Beta testing

**Week 11-12: GA Release**
- [ ] Final testing
- [ ] Release notes
- [ ] Customer communication
- [ ] Support enablement

---

## Testing Strategy

### Unit Tests

**Test: Token ID Generation**
```java
@Test
public void testTokenIdGeneration() {
    LTPAToken2 token1 = createToken("user1", true);
    LTPAToken2 token2 = createToken("user1", true);
    
    assertNotNull(token1.getTokenId());
    assertNotNull(token2.getTokenId());
    assertNotEquals(token1.getTokenId(), token2.getTokenId());
}
```

**Test: Cache Operations**
```java
@Test
public void testCacheDetectsReplay() {
    LTPATokenIdCache cache = new LTPATokenIdCache(1000, 60000);
    String tokenId = "test-token-123";
    long expiration = System.currentTimeMillis() + 60000;
    
    // First use - should return false
    assertFalse(cache.isTokenUsed(tokenId, expiration));
    
    // Second use - should return true (replay)
    assertTrue(cache.isTokenUsed(tokenId, expiration));
}
```

**Test: Expired Token Cleanup**
```java
@Test
public void testExpiredTokenCleanup() throws Exception {
    LTPATokenIdCache cache = new LTPATokenIdCache(1000, 1000);
    String tokenId = "expired-token";
    long expiration = System.currentTimeMillis() + 100; // 100ms
    
    cache.isTokenUsed(tokenId, expiration);
    assertEquals(1, cache.size());
    
    Thread.sleep(200); // Wait for expiration
    cache.cleanupExpiredTokens();
    
    assertEquals(0, cache.size());
}
```

### Integration Tests

**Test: End-to-End Replay Detection**
```java
@Test
public void testReplayDetection() throws Exception {
    // Create token with replay protection
    Map<String, Object> tokenData = new HashMap<>();
    tokenData.put(LTPAConstants.UNIQUE_ID, "user:BasicRealm/user1");
    
    Token token = factory.createToken(tokenData);
    byte[] tokenBytes = token.getBytes();
    
    // First validation - should succeed
    Token validated1 = factory.validateTokenBytes(tokenBytes);
    assertNotNull(validated1);
    
    // Second validation - should fail (replay)
    try {
        factory.validateTokenBytes(tokenBytes);
        fail("Expected InvalidTokenException for replay");
    } catch (InvalidTokenException e) {
        assertTrue(e.getMessage().contains("already been used"));
    }
}
```

### FAT Tests

**Test: Replay Protection in Web Application**
```java
@Test
public void testWebAppReplayProtection() throws Exception {
    // Login and get LTPA cookie
    WebConversation wc = new WebConversation();
    WebRequest request = new GetMethodWebRequest(protectedUrl);
    WebResponse response = wc.getResponse(request);
    
    // Extract LTPA cookie
    String ltpaCookie = getCookie(response, "LtpaToken2");
    assertNotNull(ltpaCookie);
    
    // First request with cookie - should succeed
    WebRequest request2 = new GetMethodWebRequest(protectedUrl);
    request2.setHeaderField("Cookie", "LtpaToken2=" + ltpaCookie);
    WebResponse response2 = wc.getResponse(request2);
    assertEquals(200, response2.getResponseCode());
    
    // Second request with same cookie - should fail
    WebConversation wc2 = new WebConversation();
    WebRequest request3 = new GetMethodWebRequest(protectedUrl);
    request3.setHeaderField("Cookie", "LtpaToken2=" + ltpaCookie);
    WebResponse response3 = wc2.getResponse(request3);
    assertEquals(401, response3.getResponseCode());
}
```

### Performance Tests

**Test: Cache Performance Under Load**
```java
@Test
public void testCachePerformance() {
    LTPATokenIdCache cache = new LTPATokenIdCache(100000, 60000);
    int iterations = 10000;
    
    long startTime = System.nanoTime();
    
    for (int i = 0; i < iterations; i++) {
        String tokenId = "token-" + i;
        long expiration = System.currentTimeMillis() + 60000;
        cache.isTokenUsed(tokenId, expiration);
    }
    
    long endTime = System.nanoTime();
    long avgTimeNanos = (endTime - startTime) / iterations;
    
    // Should be < 100 microseconds per operation
    assertTrue(avgTimeNanos < 100000, 
        "Average time: " + avgTimeNanos + "ns");
}
```

---

## Performance Considerations

### Memory Usage

**Cache Size Calculation**:
```
Memory per entry ≈ 100 bytes (token ID + expiration + overhead)
Default cache (100,000 entries) ≈ 10 MB
Large cache (500,000 entries) ≈ 50 MB
```

**Recommendations**:
- Small deployments (<1000 users): 50,000 entries
- Medium deployments (1000-10000 users): 100,000 entries
- Large deployments (>10000 users): 500,000 entries

### CPU Impact

**Validation Overhead**:
- Token ID generation: ~0.1ms
- Cache lookup: ~0.01ms
- Total overhead: <5% of validation time

**Optimization Strategies**:
1. Use concurrent hash map for cache
2. Batch cleanup operations
3. Lazy initialization of cache
4. Efficient token ID hashing

### Scalability

**Cluster Considerations**:

```
Option 1: Local Cache (Recommended)
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Server1 │     │ Server2 │     │ Server3 │
│ Cache1  │     │ Cache2  │     │ Cache3  │
└─────────┘     └─────────┘     └─────────┘

Pros: Simple, fast, no network overhead
Cons: Token can be used once per server
```

```
Option 2: Distributed Cache (Future Enhancement)
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Server1 │────▶│         │◀────│ Server3 │
│         │     │ Shared  │     │         │
└─────────┘     │ Cache   │     └─────────┘
                │(Redis)  │
                └─────────┘

Pros: True single-use across cluster
Cons: Network latency, complexity
```

**Recommendation**: Start with local cache (Option 1) for simplicity and performance.

---

## Migration and Compatibility

### Backward Compatibility

**Existing Tokens**:
- Tokens created before feature enablement have no token ID
- These tokens bypass replay check (logged as warning)
- Gradual migration as tokens expire and refresh

**Configuration**:
- Feature disabled by default
- No breaking changes to existing configurations
- Opt-in activation

### Migration Steps

**Step 1: Enable Monitoring**
```xml
<ltpa replayProtectionEnabled="true" 
      replayProtectionMode="monitor" />
```
- Logs replay attempts without blocking
- Assess impact on legitimate traffic

**Step 2: Reduce Token Lifetime**
```xml
<ltpa expiration="30m" 
      replayProtectionEnabled="true" 
      replayProtectionMode="monitor" />
```
- Shorter lifetime reduces risk window
- Allows faster token turnover

**Step 3: Enable Enforcement**
```xml
<ltpa expiration="30m" 
      replayProtectionEnabled="true" 
      replayProtectionMode="enforce" />
```
- Block replay attempts
- Monitor for false positives

**Step 4: Optimize Configuration**
```xml
<ltpa expiration="15m" 
      replayProtectionEnabled="true" 
      replayCacheSize="200000" />
```
- Tune based on observed metrics
- Adjust cache size for workload

### Rollback Plan

If issues arise:
1. Set `replayProtectionEnabled="false"`
2. Restart servers
3. All tokens work as before
4. No data loss or corruption

---

## Security Considerations

### Threat Model

**Mitigated Threats**:
- ✅ Token replay after interception
- ✅ Cross-client token reuse
- ✅ Session hijacking via stolen tokens
- ✅ Token theft from compromised systems

**Remaining Threats** (require additional controls):
- ⚠️ Token theft via XSS (use HttpOnly cookies)
- ⚠️ Token interception (use HTTPS)
- ⚠️ Brute force attacks (use rate limiting)
- ⚠️ Insider threats (use audit logging)

### Defense in Depth

**Layer 1: Transport Security**
```xml
<httpEndpoint httpPort="-1" httpsPort="9443" />
<ssl sslProtocol="TLSv1.3" />
```

**Layer 2: Cookie Security**
```xml
<webAppSecurity 
    httpOnlyCookies="true"
    secureCookies="true"
    sameSiteCookie="Strict" />
```

**Layer 3: Replay Protection**
```xml
<ltpa replayProtectionEnabled="true" />
```

**Layer 4: Short Token Lifetime**
```xml
<ltpa expiration="15m" />
```

**Layer 5: Monitoring & Alerting**
```xml
<logging traceSpecification="*=info:com.ibm.ws.security.token.ltpa.*=all" />
```

---

## Monitoring and Metrics

### Key Metrics

1. **Replay Detection Rate**
   - Metric: `ltpa.replay.detected.count`
   - Alert: > 10 per minute

2. **Cache Hit Rate**
   - Metric: `ltpa.cache.hit.rate`
   - Target: < 0.1% (most tokens are first use)

3. **Cache Size**
   - Metric: `ltpa.cache.size`
   - Alert: > 90% of max

4. **Validation Latency**
   - Metric: `ltpa.validation.duration`
   - Target: < 5ms overhead

### Logging

**Info Level**:
```
CWWKS4151I: LTPA replay protection is enabled with cache size [100000]
```

**Warning Level**:
```
CWWKS4152W: The LTPA replay cache size [100000] may be insufficient
```

**Error Level**:
```
CWWKS4150E: The LTPA token with ID [abc1...xyz9] has already been used
```

### Dashboards

**Recommended Metrics Dashboard**:
```
┌─────────────────────────────────────────┐
│ LTPA Replay Protection Dashboard        │
├─────────────────────────────────────────┤
│ Replay Attempts (Last Hour): 0          │
│ Cache Size: 45,231 / 100,000 (45%)     │
│ Cache Hit Rate: 0.02%                   │
│ Avg Validation Time: 2.3ms              │
│ Tokens Created (Last Hour): 1,234       │
│ Tokens Validated (Last Hour): 45,231    │
└─────────────────────────────────────────┘
```

---

## Future Enhancements

### Phase 2 Features

1. **Distributed Cache Support**
   - Redis integration
   - Hazelcast support
   - True cluster-wide replay protection

2. **Advanced Analytics**
   - ML-based anomaly detection
   - Behavioral analysis
   - Risk scoring

3. **Token Binding**
   - IP address binding (optional)
   - Device fingerprinting
   - Certificate binding

4. **Revocation API**
   - Manual token revocation
   - Bulk revocation
   - Revocation lists

### Integration Opportunities

1. **Security Event Monitoring**
   - SIEM integration
   - Real-time alerting
   - Incident response automation

2. **Compliance Reporting**
   - Audit trail generation
   - Compliance dashboards
   - Regulatory reporting

---

## Conclusion

This feature design provides comprehensive replay attack protection for LTPA tokens while maintaining backward compatibility and performance. The implementation follows established patterns from JWT token protection and can be deployed incrementally with minimal risk.

**Key Benefits**:
- ✅ Prevents token replay attacks
- ✅ Minimal performance impact (<5ms)
- ✅ Backward compatible
- ✅ Configurable and flexible
- ✅ Production-ready monitoring

**Next Steps**:
1. Review and approve design
2. Create implementation tasks
3. Begin Phase 1 development
4. Schedule security review

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-15  
**Author**: IBM Liberty Security Team  
**Reviewers**: [To be assigned]  
**Status**: Awaiting Approval