# LTPA Token Session Tracking and Revocation Feature Design

## Executive Summary

This document specifies an alternative approach to LTPA token security using **session tracking** and **token revocation lists**. Unlike client binding which validates client context, this design tracks active sessions server-side and provides explicit revocation capabilities, enabling immediate token invalidation and better session management.

**Feature ID**: `ltpaSessionTracking-1.0`  
**Target Release**: Liberty 26.0.0.x  
**Priority**: High (Security Enhancement)  
**Status**: Design Phase  
**Alternative To**: Client Binding (can be used together)

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [Session Lifecycle](#session-lifecycle)
5. [Revocation Mechanisms](#revocation-mechanisms)
6. [Configuration](#configuration)
7. [Comparison with Other Approaches](#comparison-with-other-approaches)
8. [Implementation Details](#implementation-details)

---

## Design Philosophy

### Stateful Session Management

Unlike the stateless client binding approach, this design maintains server-side session state:

```
Traditional LTPA (Stateless):
┌─────────────────────────────────────┐
│ Token contains all information      │
│ Server validates signature only     │
│ No server-side session tracking     │
│ Cannot revoke tokens before expiry  │
└─────────────────────────────────────┘

Session Tracking (Stateful):
┌─────────────────────────────────────┐
│ Token references server session     │
│ Server tracks active sessions       │
│ Can revoke tokens immediately       │
│ Provides session management APIs    │
└─────────────────────────────────────┘
```

### Key Advantages

1. **Immediate Revocation**: Invalidate tokens instantly (logout, security breach)
2. **Session Visibility**: Monitor active sessions per user
3. **Concurrent Session Control**: Limit sessions per user
4. **Audit Trail**: Track session creation, usage, termination
5. **Flexible Policies**: Apply custom session policies

### Trade-offs

**Pros**:
- ✅ Immediate token revocation
- ✅ Better session management
- ✅ Audit and compliance support
- ✅ Concurrent session limits

**Cons**:
- ❌ Requires server-side storage
- ❌ Scalability considerations (clustering)
- ❌ Performance overhead (session lookup)
- ❌ More complex than stateless approach

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────┐
│                  Session Tracking Architecture               │
└─────────────────────────────────────────────────────────────┘

Token Creation:
┌──────────────┐
│ User Login   │
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│ Create Session       │
│ - Generate Session ID│
│ - Store in Registry  │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Create LTPA Token    │
│ - Embed Session ID   │
│ - Sign & Encrypt     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Return Token         │
└──────────────────────┘

Token Validation:
┌──────────────┐
│ HTTP Request │
│ (with Token) │
└──────┬───────┘
       │
       ▼
┌──────────────────────┐
│ Extract Token        │
│ Decrypt & Verify     │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Extract Session ID   │
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│ Lookup Session       │
│ in Registry          │
└──────┬───────────────┘
       │
   ┌───┴────┐
   │        │
Found    Not Found
   │        │
   ▼        ▼
┌─────┐  ┌──────┐
│Valid│  │Reject│
│     │  │(Rev- │
│     │  │oked) │
└─────┘  └──────┘
```

---

## Core Components

### 1. Session Registry

**Purpose**: Central repository for active LTPA sessions

```java
package com.ibm.ws.security.token.ltpa.internal.session;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for tracking active LTPA token sessions.
 * Provides session lifecycle management and revocation.
 */
public class LTPASessionRegistry {
    
    /**
     * Active sessions: sessionId -> SessionInfo
     */
    private final Map<String, SessionInfo> activeSessions;
    
    /**
     * User sessions: userId -> Set<sessionId>
     */
    private final Map<String, Set<String>> userSessions;
    
    /**
     * Revoked sessions: sessionId -> revocationTime
     */
    private final Map<String, Long> revokedSessions;
    
    /**
     * Maximum sessions per user (0 = unlimited)
     */
    private final int maxSessionsPerUser;
    
    public LTPASessionRegistry(int maxSessionsPerUser) {
        this.activeSessions = new ConcurrentHashMap<>();
        this.userSessions = new ConcurrentHashMap<>();
        this.revokedSessions = new ConcurrentHashMap<>();
        this.maxSessionsPerUser = maxSessionsPerUser;
    }
    
    /**
     * Create new session.
     * 
     * @return Session ID
     * @throws MaxSessionsExceededException if user has too many sessions
     */
    public String createSession(String userId, 
                                 String clientIp,
                                 String userAgent,
                                 long expirationTime) 
            throws MaxSessionsExceededException {
        
        // Check concurrent session limit
        if (maxSessionsPerUser > 0) {
            Set<String> userSessionIds = userSessions.get(userId);
            if (userSessionIds != null && 
                userSessionIds.size() >= maxSessionsPerUser) {
                throw new MaxSessionsExceededException(
                    "User " + userId + " has reached maximum sessions: " + 
                    maxSessionsPerUser
                );
            }
        }
        
        // Generate unique session ID
        String sessionId = generateSessionId();
        
        // Create session info
        SessionInfo session = new SessionInfo(
            sessionId,
            userId,
            clientIp,
            userAgent,
            System.currentTimeMillis(),
            expirationTime
        );
        
        // Store session
        activeSessions.put(sessionId, session);
        
        // Track user sessions
        userSessions.computeIfAbsent(userId, k -> 
            ConcurrentHashMap.newKeySet()
        ).add(sessionId);
        
        return sessionId;
    }
    
    /**
     * Validate session is active and not revoked.
     */
    public boolean isSessionValid(String sessionId) {
        // Check if revoked
        if (revokedSessions.containsKey(sessionId)) {
            return false;
        }
        
        // Check if exists and not expired
        SessionInfo session = activeSessions.get(sessionId);
        if (session == null) {
            return false;
        }
        
        long currentTime = System.currentTimeMillis();
        if (session.getExpirationTime() < currentTime) {
            // Expired - remove from active
            removeSession(sessionId);
            return false;
        }
        
        // Update last access time
        session.updateLastAccessTime();
        
        return true;
    }
    
    /**
     * Revoke specific session.
     */
    public void revokeSession(String sessionId) {
        SessionInfo session = activeSessions.remove(sessionId);
        if (session != null) {
            // Add to revoked list
            revokedSessions.put(sessionId, System.currentTimeMillis());
            
            // Remove from user sessions
            Set<String> userSessionIds = userSessions.get(session.getUserId());
            if (userSessionIds != null) {
                userSessionIds.remove(sessionId);
                if (userSessionIds.isEmpty()) {
                    userSessions.remove(session.getUserId());
                }
            }
        }
    }
    
    /**
     * Revoke all sessions for a user.
     */
    public void revokeUserSessions(String userId) {
        Set<String> userSessionIds = userSessions.remove(userId);
        if (userSessionIds != null) {
            long currentTime = System.currentTimeMillis();
            for (String sessionId : userSessionIds) {
                activeSessions.remove(sessionId);
                revokedSessions.put(sessionId, currentTime);
            }
        }
    }
    
    /**
     * Get all active sessions for a user.
     */
    public Collection<SessionInfo> getUserSessions(String userId) {
        Set<String> sessionIds = userSessions.get(userId);
        if (sessionIds == null) {
            return Collections.emptyList();
        }
        
        return sessionIds.stream()
            .map(activeSessions::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    /**
     * Get session information.
     */
    public SessionInfo getSessionInfo(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    /**
     * Cleanup expired sessions and old revocations.
     */
    public void cleanup() {
        long currentTime = System.currentTimeMillis();
        
        // Remove expired sessions
        activeSessions.entrySet().removeIf(entry -> {
            SessionInfo session = entry.getValue();
            if (session.getExpirationTime() < currentTime) {
                // Also remove from user sessions
                Set<String> userSessionIds = userSessions.get(session.getUserId());
                if (userSessionIds != null) {
                    userSessionIds.remove(entry.getKey());
                }
                return true;
            }
            return false;
        });
        
        // Remove old revocations (keep for 24 hours)
        long revocationRetention = 24 * 60 * 60 * 1000;
        revokedSessions.entrySet().removeIf(entry ->
            (currentTime - entry.getValue()) > revocationRetention
        );
    }
    
    /**
     * Get statistics.
     */
    public SessionStatistics getStatistics() {
        return new SessionStatistics(
            activeSessions.size(),
            userSessions.size(),
            revokedSessions.size()
        );
    }
    
    private String generateSessionId() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64Coder.base64Encode(bytes);
    }
    
    private void removeSession(String sessionId) {
        SessionInfo session = activeSessions.remove(sessionId);
        if (session != null) {
            Set<String> userSessionIds = userSessions.get(session.getUserId());
            if (userSessionIds != null) {
                userSessionIds.remove(sessionId);
            }
        }
    }
}
```

### 2. Session Information

```java
package com.ibm.ws.security.token.ltpa.internal.session;

/**
 * Information about an active LTPA token session.
 */
public class SessionInfo {
    
    private final String sessionId;
    private final String userId;
    private final String clientIp;
    private final String userAgent;
    private final long creationTime;
    private final long expirationTime;
    private volatile long lastAccessTime;
    private volatile int accessCount;
    
    public SessionInfo(String sessionId,
                       String userId,
                       String clientIp,
                       String userAgent,
                       long creationTime,
                       long expirationTime) {
        this.sessionId = sessionId;
        this.userId = userId;
        this.clientIp = clientIp;
        this.userAgent = userAgent;
        this.creationTime = creationTime;
        this.expirationTime = expirationTime;
        this.lastAccessTime = creationTime;
        this.accessCount = 0;
    }
    
    public void updateLastAccessTime() {
        this.lastAccessTime = System.currentTimeMillis();
        this.accessCount++;
    }
    
    // Getters...
    public String getSessionId() { return sessionId; }
    public String getUserId() { return userId; }
    public String getClientIp() { return clientIp; }
    public String getUserAgent() { return userAgent; }
    public long getCreationTime() { return creationTime; }
    public long getExpirationTime() { return expirationTime; }
    public long getLastAccessTime() { return lastAccessTime; }
    public int getAccessCount() { return accessCount; }
    
    public long getIdleTime() {
        return System.currentTimeMillis() - lastAccessTime;
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() > expirationTime;
    }
}
```

### 3. Enhanced LTPAToken2Factory

```java
public class LTPAToken2Factory implements TokenFactory {
    
    private boolean sessionTrackingEnabled;
    private LTPASessionRegistry sessionRegistry;
    
    @Override
    public void initialize(Map tokenFactoryMap) {
        // Existing initialization...
        
        sessionTrackingEnabled = (Boolean) tokenFactoryMap.getOrDefault(
            LTPAConstants.SESSION_TRACKING_ENABLED, false
        );
        
        if (sessionTrackingEnabled) {
            int maxSessionsPerUser = (Integer) tokenFactoryMap.getOrDefault(
                LTPAConstants.MAX_SESSIONS_PER_USER, 0
            );
            
            sessionRegistry = new LTPASessionRegistry(maxSessionsPerUser);
        }
    }
    
    @Override
    public Token createToken(Map tokenData) 
            throws TokenCreationFailedException {
        
        String userUniqueId = getUniqueId(tokenData);
        
        // Create session if tracking enabled
        String sessionId = null;
        if (sessionTrackingEnabled) {
            HttpServletRequest request = (HttpServletRequest) 
                tokenData.get(LTPAConstants.HTTP_REQUEST);
            
            try {
                sessionId = sessionRegistry.createSession(
                    userUniqueId,
                    request.getRemoteAddr(),
                    request.getHeader("User-Agent"),
                    calculateExpirationTime()
                );
            } catch (MaxSessionsExceededException e) {
                throw new TokenCreationFailedException(
                    "Maximum concurrent sessions exceeded", e
                );
            }
        }
        
        return new LTPAToken2(
            userUniqueId,
            expirationInMinutes,
            maxLifetimeInMinutes,
            refreshThresholdInMinutes,
            primarySharedKey,
            primaryPrivateKey,
            primaryPublicKey,
            replayProtectionEnabled,
            clientBindingHash,
            sessionId  // NEW: Session ID
        );
    }
    
    @Override
    public Token validateTokenBytes(byte[] tokenBytes, String... removeAttributes)
            throws InvalidTokenException, TokenExpiredException {
        
        // Existing validation...
        Token validatedToken = new LTPAToken2(tokenBytes, ...);
        
        // Validate session if tracking enabled
        if (sessionTrackingEnabled && validatedToken != null) {
            validateSession(validatedToken);
        }
        
        return validatedToken;
    }
    
    private void validateSession(Token token) 
            throws InvalidTokenException {
        
        if (!(token instanceof LTPAToken2)) {
            return;
        }
        
        LTPAToken2 ltpaToken = (LTPAToken2) token;
        String sessionId = ltpaToken.getSessionId();
        
        if (sessionId == null || sessionId.isEmpty()) {
            // Token created before session tracking enabled
            return;
        }
        
        if (!sessionRegistry.isSessionValid(sessionId)) {
            // Session revoked or expired
            Tr.error(tc, "LTPA_SESSION_INVALID", sessionId);
            throw new InvalidTokenException(
                "LTPA session is invalid or has been revoked"
            );
        }
    }
}
```

---

## Session Lifecycle

### Creation Flow

```
1. User authenticates
2. Create session in registry
3. Generate session ID
4. Embed session ID in LTPA token
5. Return token to client
```

### Validation Flow

```
1. Receive token from client
2. Decrypt and verify token
3. Extract session ID
4. Lookup session in registry
5. Check if revoked
6. Check if expired
7. Update last access time
8. Allow or reject request
```

### Termination Flow

```
Explicit Logout:
1. User clicks logout
2. Extract session ID from token
3. Revoke session in registry
4. Clear client cookie

Idle Timeout:
1. Periodic cleanup task runs
2. Check last access time
3. Revoke idle sessions
4. Remove from registry

Expiration:
1. Token expiration time reached
2. Automatic removal from registry
3. Subsequent requests rejected
```

---

## Revocation Mechanisms

### 1. Single Session Revocation

```java
// Revoke specific session (logout)
sessionRegistry.revokeSession(sessionId);
```

### 2. User Session Revocation

```java
// Revoke all sessions for user (security breach)
sessionRegistry.revokeUserSessions(userId);
```

### 3. Bulk Revocation

```java
// Revoke sessions matching criteria
sessionRegistry.revokeSessions(session -> 
    session.getClientIp().startsWith("10.0.0.")
);
```

### 4. Emergency Revocation

```java
// Revoke all sessions (system-wide security event)
sessionRegistry.revokeAllSessions();
```

---

## Configuration

### Basic Configuration

```xml
<server>
    <featureManager>
        <feature>appSecurity-3.0</feature>
        <feature>ltpaSessionTracking-1.0</feature>
    </featureManager>
    
    <ltpa 
        expiration="30m"
        sessionTrackingEnabled="true" />
</server>
```

### With Concurrent Session Limits

```xml
<ltpa 
    expiration="30m"
    sessionTrackingEnabled="true"
    maxSessionsPerUser="3" />
```

### With Idle Timeout

```xml
<ltpa 
    expiration="30m"
    sessionTrackingEnabled="true"
    maxSessionsPerUser="5"
    sessionIdleTimeout="15m" />
```

### Combined with Other Features

```xml
<ltpa 
    expiration="30m"
    replayProtectionEnabled="true"
    clientBindingEnabled="true"
    clientBindingStrategy="fingerprint"
    sessionTrackingEnabled="true"
    maxSessionsPerUser="3" />
```

---

## Comparison with Other Approaches

### vs. Client Binding

| Feature | Session Tracking | Client Binding |
|---------|------------------|----------------|
| **Revocation** | ✅ Immediate | ❌ Not possible |
| **Session Limits** | ✅ Supported | ❌ Not supported |
| **Audit Trail** | ✅ Complete | ⚠️ Limited |
| **Scalability** | ⚠️ Requires storage | ✅ Stateless |
| **Performance** | ⚠️ Session lookup | ✅ No lookup |
| **Clustering** | ⚠️ Complex | ✅ Simple |

### vs. Replay Protection

| Feature | Session Tracking | Replay Protection |
|---------|------------------|-------------------|
| **Prevents Reuse** | ✅ Yes | ✅ Yes |
| **Revocation** | ✅ Immediate | ❌ Not possible |
| **Session Mgmt** | ✅ Full control | ❌ None |
| **Storage** | ⚠️ Session data | ⚠️ Token IDs only |

### Recommended Combinations

**Maximum Security**:
```xml
<ltpa 
    replayProtectionEnabled="true"
    clientBindingEnabled="true"
    sessionTrackingEnabled="true" />
```

**High Security + Usability**:
```xml
<ltpa 
    replayProtectionEnabled="true"
    sessionTrackingEnabled="true" />
```

**Basic Security**:
```xml
<ltpa 
    sessionTrackingEnabled="true" />
```

---

## Implementation Details

### Session Storage Options

**Option 1: In-Memory (Default)**
- Fast, simple
- Lost on restart
- Not shared across cluster

**Option 2: Database**
- Persistent
- Shared across cluster
- Slower performance

**Option 3: Distributed Cache (Redis)**
- Fast
- Shared across cluster
- Requires external dependency

### Clustering Considerations

**Sticky Sessions** (Recommended):
```
Load Balancer → Server 1 (User A sessions)
              → Server 2 (User B sessions)
```

**Session Replication**:
```
Server 1 ←→ Server 2 (replicate sessions)
```

**Shared Storage**:
```
Server 1 → Database ← Server 2
```

---

## Conclusion

Session tracking provides powerful session management and immediate revocation capabilities at the cost of server-side state. It complements client binding and replay protection to create a comprehensive security solution.

**Best For**:
- Applications requiring immediate logout
- Concurrent session limits
- Detailed audit trails
- Session management APIs

**Not Ideal For**:
- Stateless microservices
- High-scale distributed systems
- Simple authentication needs

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-15  
**Author**: IBM Liberty Security Team  
**Status**: Design Phase