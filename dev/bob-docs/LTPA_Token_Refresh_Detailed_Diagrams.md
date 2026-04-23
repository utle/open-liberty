# LTPA Token Refresh - Detailed Diagrams and Flow Analysis

## Executive Summary

This document provides comprehensive visual diagrams and detailed explanations of how LTPA token refresh works in IBM WebSphere Liberty. It covers the complete lifecycle, decision logic, timing calculations, and implementation details.

**Target Audience**: Developers, Security Engineers, System Architects  
**Last Updated**: 2026-04-15

---

## Table of Contents

1. [LTPA Token Lifecycle Overview](#ltpa-token-lifecycle-overview)
2. [Token Refresh Decision Logic](#token-refresh-decision-logic)
3. [Detailed Refresh Flow](#detailed-refresh-flow)
4. [Timing Calculations](#timing-calculations)
5. [Implementation Architecture](#implementation-architecture)
6. [Sequence Diagrams](#sequence-diagrams)
7. [State Transitions](#state-transitions)
8. [Configuration Impact](#configuration-impact)

---

## LTPA Token Lifecycle Overview

### Complete Token Timeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LTPA Token Complete Lifecycle                         │
└─────────────────────────────────────────────────────────────────────────────┘

Time:     0m          10m          15m          20m          30m          60m
          │           │            │            │            │            │
          ▼           ▼            ▼            ▼            ▼            ▼
          
Creation  │◄────── Normal Use ────►│◄─ Refresh Window ─►│  Expired    Max Life
   │      │                        │                     │     │           │
   │      │                        │                     │     │           │
   │      │    Token Valid         │   Token Valid       │     │           │
   │      │    No Refresh          │   Refresh Triggered │     │           │
   │      │                        │                     │     │           │
   │      │                        │                     │     │           │
   ▼      ▼                        ▼                     ▼     ▼           ▼
[Create] [Use]                  [Refresh]            [Reject] [Force      [Hard
 Token   Token                   Token                Token   Re-auth]    Limit]
                                                                           
Configuration:
- expiration = 15m
- refreshThreshold = 5m  
- maxLifetime = 60m

Key Points:
• 0-10m:  Token valid, no refresh needed
• 10-15m: Token valid, refresh window (5m threshold)
• 15m:    Token expires, must refresh or reject
• 15-60m: Can refresh if within maxLifetime
• 60m:    Absolute limit, must re-authenticate
```

### Token States

```
┌──────────────────────────────────────────────────────────────┐
│                    LTPA Token States                          │
└──────────────────────────────────────────────────────────────┘

┌─────────────┐
│   CREATED   │  Token just created
│             │  • creationTime = now
│  State: 0   │  • expirationTime = now + expiration
└──────┬──────┘  • maxLifetimeTime = now + maxLifetime
       │
       │ User makes request
       ▼
┌─────────────┐
│    VALID    │  Token is valid and fresh
│             │  • currentTime < (expirationTime - refreshThreshold)
│  State: 1   │  • No refresh needed
└──────┬──────┘  • Continue using token
       │
       │ Time passes
       ▼
┌─────────────┐
│  REFRESH    │  Token in refresh window
│   WINDOW    │  • (expirationTime - currentTime) ≤ refreshThreshold
│  State: 2   │  • currentTime < maxLifetimeTime
└──────┬──────┘  • Trigger refresh on next request
       │
       │ Refresh triggered
       ▼
┌─────────────┐
│  REFRESHED  │  New token created
│             │  • New expirationTime = now + expiration
│  State: 3   │  • Same maxLifetimeTime (preserved)
└──────┬──────┘  • Cookie updated
       │
       │ Continue using
       ▼
┌─────────────┐
│   EXPIRED   │  Token past expiration
│             │  • currentTime > expirationTime
│  State: 4   │  • Can still refresh if < maxLifetime
└──────┬──────┘  • Otherwise reject
       │
       │ Max lifetime reached
       ▼
┌─────────────┐
│  MAX LIFE   │  Absolute limit reached
│  EXCEEDED   │  • currentTime > maxLifetimeTime
│  State: 5   │  • Cannot refresh
└─────────────┘  • Must re-authenticate
```

---

## Token Refresh Decision Logic

### Complete Decision Tree

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LTPA Token Refresh Decision Logic                         │
└─────────────────────────────────────────────────────────────────────────────┘

                        [HTTP Request with LTPA Cookie]
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  Extract LTPA Token   │
                        │  from Cookie          │
                        └───────────┬───────────┘
                                    │
                                    ▼
                        ┌───────────────────────┐
                        │  Decrypt & Verify     │
                        │  Token Signature      │
                        └───────────┬───────────┘
                                    │
                        ┌───────────┴───────────┐
                        │                       │
                    Valid?                  Invalid?
                        │                       │
                        ▼                       ▼
            ┌───────────────────┐   ┌──────────────────┐
            │ Parse Token Data  │   │ Reject Request   │
            │ - creationTime    │   │ Return 401       │
            │ - expirationTime  │   └──────────────────┘
            │ - maxLifetime     │
            └─────────┬─────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ currentTime =     │
            │ System.now()      │
            └─────────┬─────────┘
                      │
                      ▼
        ┌─────────────────────────────┐
        │ Check: currentTime >        │
        │        maxLifetimeTime?     │
        └─────────┬───────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
    YES │               NO  │
        │                   │
        ▼                   ▼
┌───────────────┐   ┌──────────────────┐
│ Max Lifetime  │   │ Check: currentTime│
│ Exceeded      │   │ > expirationTime? │
│               │   └────────┬─────────┘
│ REJECT        │            │
│ Force Re-auth │   ┌────────┴────────┐
└───────────────┘   │                 │
                YES │             NO  │
                    │                 │
                    ▼                 ▼
        ┌──────────────────┐  ┌─────────────────────┐
        │ Token Expired    │  │ Calculate:          │
        │ But < MaxLife    │  │ timeRemaining =     │
        │                  │  │ expiration -        │
        │ Can Refresh      │  │ currentTime         │
        │ if configured    │  └──────────┬──────────┘
        └────────┬─────────┘             │
                 │                       ▼
                 │           ┌──────────────────────┐
                 │           │ Check: timeRemaining │
                 │           │ ≤ refreshThreshold?  │
                 │           └──────────┬───────────┘
                 │                      │
                 │           ┌──────────┴──────────┐
                 │           │                     │
                 │       YES │                 NO  │
                 │           │                     │
                 └───────────┤                     │
                             ▼                     ▼
                 ┌──────────────────────┐  ┌─────────────┐
                 │ REFRESH TOKEN        │  │ USE EXISTING│
                 │                      │  │ TOKEN       │
                 │ 1. Create new token  │  │             │
                 │ 2. Reset expiration  │  │ No refresh  │
                 │ 3. Keep maxLifetime  │  │ needed      │
                 │ 4. Update cookie     │  └──────┬──────┘
                 └──────────┬───────────┘         │
                            │                     │
                            └──────────┬──────────┘
                                       │
                                       ▼
                            ┌──────────────────┐
                            │ GRANT ACCESS     │
                            │ Process Request  │
                            └──────────────────┘
```

### Refresh Conditions Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                  Token Refresh Conditions                        │
└─────────────────────────────────────────────────────────────────┘

Condition 1: Token Must Be Valid
├─ Signature verified ✓
├─ Not corrupted ✓
└─ Properly formatted ✓

Condition 2: Within Max Lifetime
├─ currentTime < maxLifetimeTime ✓
└─ If exceeded → Force re-authentication

Condition 3: In Refresh Window
├─ (expirationTime - currentTime) ≤ refreshThreshold ✓
└─ If not in window → Use existing token

Condition 4: Refresh Threshold Configured
├─ refreshThreshold > 0 ✓
└─ If 0 → No automatic refresh

ALL CONDITIONS MUST BE TRUE FOR REFRESH
```

---

## Detailed Refresh Flow

### Step-by-Step Refresh Process

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Detailed LTPA Token Refresh Flow                          │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: REQUEST RECEPTION
┌──────────────────────────────────────┐
│ 1. Client sends HTTP request         │
│    GET /app/protected                │
│    Cookie: LtpaToken2=<encrypted>    │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 2. SSOAuthenticator intercepts       │
│    - Extract cookie value            │
│    - Base64 decode                   │
└────────────────┬─────────────────────┘
                 │
                 ▼

PHASE 2: TOKEN VALIDATION
┌──────────────────────────────────────┐
│ 3. LTPAToken2Factory.validate()      │
│    - Decrypt with shared key         │
│    - Verify signature                │
│    - Parse token data                │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 4. Extract token attributes:         │
│    - u: user unique ID               │
│    - expire: expiration time (ms)    │
│    - creation: creation time (ms)    │
│    - maxlife: max lifetime (ms)      │
│    - type: token type                │
└────────────────┬─────────────────────┘
                 │
                 ▼

PHASE 3: REFRESH DECISION
┌──────────────────────────────────────┐
│ 5. Calculate timing values:          │
│    currentTime = System.now()        │
│    timeRemaining = expire - current  │
│    tokenAge = current - creation     │
│    thresholdMs = threshold * 60000   │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 6. Check max lifetime:               │
│    if (tokenAge > maxlife) {         │
│        return REJECT                 │
│    }                                 │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 7. Check refresh threshold:          │
│    if (timeRemaining ≤ thresholdMs) {│
│        shouldRefresh = true          │
│    }                                 │
└────────────────┬─────────────────────┘
                 │
                 ▼

PHASE 4: TOKEN REFRESH (if needed)
┌──────────────────────────────────────┐
│ 8. Create new token:                 │
│    newToken = new LTPAToken2(        │
│        userUniqueId,                 │
│        expirationMinutes,            │
│        maxLifetimeMinutes,           │
│        refreshThresholdMinutes,      │
│        sharedKey,                    │
│        privateKey,                   │
│        publicKey                     │
│    )                                 │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 9. New token attributes:             │
│    - creation: currentTime           │
│    - expire: current + expiration    │
│    - maxlife: ORIGINAL creation +    │
│               maxLifetime            │
│    - u: same user ID                 │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 10. Encrypt and sign new token       │
│     - Serialize attributes           │
│     - Encrypt with shared key        │
│     - Sign with private key          │
│     - Base64 encode                  │
└────────────────┬─────────────────────┘
                 │
                 ▼

PHASE 5: COOKIE UPDATE
┌──────────────────────────────────────┐
│ 11. Update response cookie:          │
│     Set-Cookie: LtpaToken2=<new>;    │
│                 Path=/;              │
│                 HttpOnly;            │
│                 Secure;              │
│                 SameSite=Lax         │
└────────────────┬─────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────┐
│ 12. Create authenticated subject     │
│     - Add user credentials           │
│     - Add token to subject           │
│     - Set security context           │
└────────────────┬─────────────────────┘
                 │
                 ▼

PHASE 6: REQUEST PROCESSING
┌──────────────────────────────────────┐
│ 13. Grant access to resource         │
│     - Process original request       │
│     - Return response with new cookie│
└──────────────────────────────────────┘
```

---

## Timing Calculations

### Time-Based Refresh Logic

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LTPA Token Timing Calculations                            │
└─────────────────────────────────────────────────────────────────────────────┘

Given Configuration:
├─ expiration = 15 minutes
├─ refreshThreshold = 5 minutes
└─ maxLifetime = 60 minutes

Token Created at T0 = 0 minutes:
├─ creationTime = T0
├─ expirationTime = T0 + 15m = 15m
└─ maxLifetimeTime = T0 + 60m = 60m

Timeline Analysis:

T = 0m (Creation)
├─ timeRemaining = 15m - 0m = 15m
├─ inRefreshWindow = (15m ≤ 5m) = FALSE
└─ Action: Use token, no refresh

T = 5m (Normal use)
├─ timeRemaining = 15m - 5m = 10m
├─ inRefreshWindow = (10m ≤ 5m) = FALSE
└─ Action: Use token, no refresh

T = 10m (Entering refresh window)
├─ timeRemaining = 15m - 10m = 5m
├─ inRefreshWindow = (5m ≤ 5m) = TRUE
├─ withinMaxLife = (10m < 60m) = TRUE
└─ Action: REFRESH TOKEN
    ├─ New creationTime = 10m
    ├─ New expirationTime = 10m + 15m = 25m
    └─ Same maxLifetimeTime = 60m (preserved!)

T = 11m (After refresh)
├─ timeRemaining = 25m - 11m = 14m
├─ inRefreshWindow = (14m ≤ 5m) = FALSE
└─ Action: Use refreshed token

T = 20m (Second refresh window)
├─ timeRemaining = 25m - 20m = 5m
├─ inRefreshWindow = (5m ≤ 5m) = TRUE
├─ withinMaxLife = (20m < 60m) = TRUE
└─ Action: REFRESH TOKEN AGAIN
    ├─ New creationTime = 20m
    ├─ New expirationTime = 20m + 15m = 35m
    └─ Same maxLifetimeTime = 60m (still preserved!)

T = 55m (Near max lifetime)
├─ timeRemaining = 35m - 55m = -20m (expired!)
├─ tokenAge = 55m - 0m = 55m
├─ withinMaxLife = (55m < 60m) = TRUE
└─ Action: Can still refresh (expired but < maxLife)
    ├─ New creationTime = 55m
    ├─ New expirationTime = 55m + 15m = 70m
    └─ But maxLifetimeTime = 60m (will expire at 60m!)

T = 60m (Max lifetime reached)
├─ tokenAge = 60m - 0m = 60m
├─ withinMaxLife = (60m < 60m) = FALSE
└─ Action: REJECT - Force re-authentication

T = 65m (Beyond max lifetime)
├─ tokenAge = 65m - 0m = 65m
├─ withinMaxLife = (65m < 60m) = FALSE
└─ Action: REJECT - Must re-authenticate
```

### Refresh Frequency Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Token Refresh Frequency Analysis                          │
└─────────────────────────────────────────────────────────────────────────────┘

Configuration: expiration=15m, refreshThreshold=5m, maxLifetime=60m

Refresh Opportunities:
├─ Window 1: 10m - 15m (5 minute window)
├─ Window 2: 20m - 25m (5 minute window) [after 1st refresh]
├─ Window 3: 30m - 35m (5 minute window) [after 2nd refresh]
├─ Window 4: 40m - 45m (5 minute window) [after 3rd refresh]
└─ Window 5: 50m - 55m (5 minute window) [after 4th refresh]

Maximum Refreshes: 5 times before hitting maxLifetime at 60m

Refresh Pattern:
0m ──────► 10m ──────► 20m ──────► 30m ──────► 40m ──────► 50m ──────► 60m
[Create]   [Refresh1]  [Refresh2]  [Refresh3]  [Refresh4]  [Refresh5]  [Reject]
           ↑           ↑           ↑           ↑           ↑           ↑
           Window 1    Window 2    Window 3    Window 4    Window 5    Max Life

Active Request Frequency Impact:
├─ High frequency (requests every minute):
│  └─ Token refreshed at first request in each window
│     └─ Refreshes at: 10m, 20m, 30m, 40m, 50m
│
├─ Medium frequency (requests every 5 minutes):
│  └─ Token refreshed when request falls in window
│     └─ Refreshes at: 10m, 25m, 35m, 45m, 55m
│
└─ Low frequency (requests every 15 minutes):
   └─ Token may expire between requests
      └─ Refreshes at: 15m (expired, but < maxLife)
```

---

## Implementation Architecture

### Component Interaction Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LTPA Token Refresh Architecture                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐
│   HTTP Client   │
│   (Browser)     │
└────────┬────────┘
         │ GET /app/protected
         │ Cookie: LtpaToken2=xxx
         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Liberty Server                                      │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    Web Container Security                           │    │
│  │                                                                     │    │
│  │  ┌──────────────────────────────────────────────────────────┐     │    │
│  │  │              SSOAuthenticator                             │     │    │
│  │  │                                                           │     │    │
│  │  │  1. Extract LTPA cookie                                  │     │    │
│  │  │  2. Call TokenFactory.validate()                         │     │    │
│  │  │  3. Check if token refreshed                             │     │    │
│  │  │  4. Update cookie if needed                              │     │    │
│  │  └────────────────────┬─────────────────────────────────────┘     │    │
│  │                       │                                            │    │
│  └───────────────────────┼────────────────────────────────────────────┘    │
│                          │                                                  │
│                          ▼                                                  │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    LTPA Token Service                               │    │
│  │                                                                     │    │
│  │  ┌──────────────────────────────────────────────────────────┐     │    │
│  │  │           LTPAToken2Factory                               │     │    │
│  │  │                                                           │     │    │
│  │  │  • validateTokenBytes()                                  │     │    │
│  │  │    ├─ Decrypt token                                      │     │    │
│  │  │    ├─ Verify signature                                   │     │    │
│  │  │    ├─ Parse attributes                                   │     │    │
│  │  │    └─ Check expiration                                   │     │    │
│  │  │                                                           │     │    │
│  │  │  • createToken()                                         │     │    │
│  │  │    ├─ Create new LTPAToken2                             │     │    │
│  │  │    ├─ Set expiration                                     │     │    │
│  │  │    ├─ Preserve maxLifetime                              │     │    │
│  │  │    └─ Encrypt and sign                                   │     │    │
│  │  └────────────────────┬─────────────────────────────────────┘     │    │
│  │                       │                                            │    │
│  └───────────────────────┼────────────────────────────────────────────┘    │
│                          │                                                  │
│                          ▼                                                  │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                    LTPAToken2                                       │    │
│  │                                                                     │    │
│  │  Token Attributes:                                                 │    │
│  │  ├─ u: user unique ID                                              │    │
│  │  ├─ expire: expiration time (ms)                                   │    │
│  │  ├─ creation: creation time (ms)                                   │    │
│  │  ├─ maxlife: max lifetime (ms)                                     │    │
│  │  ├─ type: token type                                               │    │
│  │  └─ host: optional host binding                                    │    │
│  │                                                                     │    │
│  │  Methods:                                                          │    │
│  │  ├─ shouldRefreshToken()                                           │    │
│  │  ├─ isExpired()                                                    │    │
│  │  ├─ isWithinMaxLifetime()                                          │    │
│  │  └─ getBytes()                                                     │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Classes and Methods

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Key Implementation Classes                                │
└─────────────────────────────────────────────────────────────────────────────┘

1. SSOAuthenticator
   Location: com.ibm.ws.webcontainer.security.internal.SSOAuthenticator
   
   Key Methods:
   ├─ authenticate(WebRequest)
   │  └─ Main entry point for SSO authentication
   │
   ├─ handleSSO(HttpServletRequest, HttpServletResponse)
   │  └─ Process LTPA cookie and validate token
   │
   ├─ shouldUpdateSSOCookie(HttpServletRequest, Subject)
   │  └─ Determine if cookie needs updating after refresh
   │
   └─ createSSOCookie(HttpServletRequest, HttpServletResponse, Subject)
      └─ Create/update LTPA cookie in response

2. LTPAToken2Factory
   Location: com.ibm.ws.security.token.ltpa.internal.LTPAToken2Factory
   
   Key Methods:
   ├─ initialize(Map)
   │  └─ Initialize with configuration (expiration, threshold, maxLife)
   │
   ├─ createToken(Map)
   │  └─ Create new LTPA token with user data
   │
   └─ validateTokenBytes(byte[])
      └─ Validate and potentially refresh token

3. LTPAToken2
   Location: com.ibm.ws.security.token.ltpa.internal.LTPAToken2
   
   Key Methods:
   ├─ shouldRefreshToken()
   │  └─ Check if token is in refresh window
   │
   ├─ isExpired()
   │  └─ Check if token has expired
   │
   ├─ isWithinMaxLifetime()
   │  └─ Check if token is within max lifetime
   │
   └─ getBytes()
      └─ Serialize token to byte array

4. LTPAConfigurationImpl
   Location: com.ibm.ws.security.token.ltpa.internal.LTPAConfigurationImpl
   
   Configuration Properties:
   ├─ expiration (default: 15m)
   ├─ refreshThreshold (default: 5m)
   ├─ maxLifetime (default: 60m)
   ├─ keysFileName
   └─ keysPassword
```

---

## Sequence Diagrams

### Normal Token Refresh Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Normal Token Refresh Sequence                             │
└─────────────────────────────────────────────────────────────────────────────┘

Client          WebContainer    SSOAuthenticator    TokenFactory    LTPAToken2
  │                  │                 │                 │              │
  │ GET /protected   │                 │                 │              │
  │ Cookie: Token1   │                 │                 │              │
  ├─────────────────►│                 │                 │              │
  │                  │                 │                 │              │
  │                  │ authenticate()  │                 │              │
  │                  ├────────────────►│                 │              │
  │                  │                 │                 │              │
  │                  │                 │ validate(bytes) │              │
  │                  │                 ├────────────────►│              │
  │                  │                 │                 │              │
  │                  │                 │                 │ decrypt()    │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ verify()     │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ shouldRefresh()
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ TRUE         │
  │                  │                 │                 │◄─────────────┤
  │                  │                 │                 │              │
  │                  │                 │ createToken()   │              │
  │                  │                 ├────────────────►│              │
  │                  │                 │                 │              │
  │                  │                 │                 │ new Token2   │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ encrypt()    │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ sign()       │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ Token2 bytes │
  │                  │                 │                 │◄─────────────┤
  │                  │                 │                 │              │
  │                  │                 │ Token2          │              │
  │                  │                 │◄────────────────┤              │
  │                  │                 │                 │              │
  │                  │ shouldUpdate()  │                 │              │
  │                  │◄────────────────┤                 │              │
  │                  │                 │                 │              │
  │                  │ TRUE            │                 │              │
  │                  ├────────────────►│                 │              │
  │                  │                 │                 │              │
  │                  │ updateCookie()  │                 │              │
  │                  │◄────────────────┤                 │              │
  │                  │                 │                 │              │
  │ 200 OK           │                 │                 │              │
  │ Set-Cookie:      │                 │                 │              │
  │   Token2         │                 │                 │              │
  │◄─────────────────┤                 │                 │              │
  │                  │                 │                 │              │
```

### Token Expiration and Rejection Sequence

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                Token Expiration and Rejection Sequence                       │
└─────────────────────────────────────────────────────────────────────────────┘

Client          WebContainer    SSOAuthenticator    TokenFactory    LTPAToken2
  │                  │                 │                 │              │
  │ GET /protected   │                 │                 │              │
  │ Cookie: OldToken │                 │                 │              │
  ├─────────────────►│                 │                 │              │
  │                  │                 │                 │              │
  │                  │ authenticate()  │                 │              │
  │                  ├────────────────►│                 │              │
  │                  │                 │                 │              │
  │                  │                 │ validate(bytes) │              │
  │                  │                 ├────────────────►│              │
  │                  │                 │                 │              │
  │                  │                 │                 │ decrypt()    │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ verify()     │
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ isWithinMaxLife()
  │                  │                 │                 ├─────────────►│
  │                  │                 │                 │              │
  │                  │                 │                 │ FALSE        │
  │                  │                 │                 │◄─────────────┤
  │                  │                 │                 │              │
  │                  │                 │ TokenExpired    │              │
  │                  │                 │ Exception       │              │
  │                  │                 │◄────────────────┤              │
  │                  │                 │                 │              │
  │                  │ AuthResult.     │                 │              │
  │                  │ FAILURE         │                 │              │
  │                  │◄────────────────┤                 │              │
  │                  │                 │                 │              │
  │ 401 Unauthorized │                 │                 │              │
  │ WWW-Authenticate │                 │                 │              │
  │◄─────────────────┤                 │                 │              │
  │                  │                 │                 │              │
  │ Re-authenticate  │                 │                 │              │
  │ (Login form)     │                 │                 │              │
  │                  │                 │                 │              │
```

---

## State Transitions

### Token State Machine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    LTPA Token State Machine                                  │
└─────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────┐
                    │   User Login     │
                    │  (Initial Auth)  │
                    └────────┬─────────┘
                             │
                             │ Create token
                             ▼
                    ┌──────────────────┐
                    │     CREATED      │
                    │                  │
                    │ • creationTime   │
                    │ • expirationTime │
                    │ • maxLifetime    │
                    └────────┬─────────┘
                             │
                             │ Time < (exp - threshold)
                             ▼
                    ┌──────────────────┐
                    │      VALID       │◄──────────┐
                    │                  │           │
                    │ • Token fresh    │           │
                    │ • No refresh     │           │
                    └────────┬─────────┘           │
                             │                     │
                             │ Time ≥ (exp - threshold)
                             │ AND Time < maxLife  │
                             ▼                     │
                    ┌──────────────────┐           │
                    │  REFRESH WINDOW  │           │
                    │                  │           │
                    │ • Can refresh    │           │
                    │ • Still valid    │           │
                    └────────┬─────────┘           │
                             │                     │
                             │ Request received    │
                             ▼                     │
                    ┌──────────────────┐           │
                    │   REFRESHING     │           │
                    │                  │           │
                    │ • Creating new   │           │
                    │ • Updating cookie│           │
                    └────────┬─────────┘           │
                             │                     │
                             │ Refresh complete    │
                             └─────────────────────┘
                             
                    ┌──────────────────┐
                    │     EXPIRED      │
                    │                  │
                    │ • Time > exp     │
                    │ • Time < maxLife │
                    └────────┬─────────┘
                             │
                             │ Can still refresh
                             ▼
                    ┌──────────────────┐
                    │  LATE REFRESH    │
                    │                  │
                    │ • Expired but OK │
                    │ • Create new     │
                    └────────┬─────────┘
                             │
                             │ Refresh complete
                             └─────────────────────┐
                                                   │
                    ┌──────────────────┐           │
                    │  MAX LIFETIME    │           │
                    │    EXCEEDED      │           │
                    │                  │           │
                    │ • Time > maxLife │           │
                    │ • Cannot refresh │           │
                    └────────┬─────────┘           │
                             │                     │
                             │ Force re-auth       │
                             ▼                     │
                    ┌──────────────────┐           │
                    │    REJECTED      │           │
                    │                  │           │
                    │ • Return 401     │           │
                    │ • Clear cookie   │           │
                    └──────────────────┘           │
                                                   │
                                                   ▼
                                          ┌──────────────────┐
                                          │   VALID (new)    │
                                          │                  │
                                          │ • Fresh token    │
                                          │ • New expiration │
                                          └──────────────────┘
```

---

## Configuration Impact

### Different Configuration Scenarios

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Configuration Impact Analysis                             │
└─────────────────────────────────────────────────────────────────────────────┘

SCENARIO 1: Aggressive Refresh (High Security)
Configuration:
├─ expiration = 10m
├─ refreshThreshold = 3m
└─ maxLifetime = 30m

Timeline:
0m ──► 7m ──► 10m ──► 17m ──► 20m ──► 27m ──► 30m
[Create] [Refresh1] [Expire] [Refresh2] [Expire] [Refresh3] [MaxLife]

Characteristics:
├─ Frequent refreshes (every 10 minutes)
├─ Short refresh window (3 minutes)
├─ Maximum 3 refreshes before re-auth
└─ Best for: High-security environments

─────────────────────────────────────────────────────────────────────────────

SCENARIO 2: Balanced Refresh (Recommended)
Configuration:
├─ expiration = 15m
├─ refreshThreshold = 5m
└─ maxLifetime = 60m

Timeline:
0m ──► 10m ──► 15m ──► 25m ──► 30m ──► 45m ──► 60m
[Create] [Refresh1] [Expire] [Refresh2] [Expire] [Refresh3] [MaxLife]

Characteristics:
├─ Moderate refresh frequency (every 15 minutes)
├─ Reasonable refresh window (5 minutes)
├─ Maximum 4 refreshes before re-auth
└─ Best for: Enterprise applications

─────────────────────────────────────────────────────────────────────────────

SCENARIO 3: Relaxed Refresh (Low Security)
Configuration:
├─ expiration = 30m
├─ refreshThreshold = 10m
└─ maxLifetime = 120m

Timeline:
0m ──► 20m ──► 30m ──► 50m ──► 60m ──► 90m ──► 120m
[Create] [Refresh1] [Expire] [Refresh2] [Expire] [Refresh3] [MaxLife]

Characteristics:
├─ Infrequent refreshes (every 30 minutes)
├─ Large refresh window (10 minutes)
├─ Maximum 4 refreshes before re-auth
└─ Best for: Internal applications

─────────────────────────────────────────────────────────────────────────────

SCENARIO 4: No Refresh (Disabled)
Configuration:
├─ expiration = 15m
├─ refreshThreshold = 0m (disabled)
└─ maxLifetime = 15m (same as expiration)

Timeline:
0m ──────────────────────► 15m
[Create]                   [Expire & Reject]

Characteristics:
├─ No automatic refresh
├─ Token expires after 15 minutes
├─ Must re-authenticate after expiration
└─ Best for: Stateless APIs, testing
```

### Refresh Threshold Impact

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Refresh Threshold Impact                                  │
└─────────────────────────────────────────────────────────────────────────────┘

Given: expiration = 15m, maxLifetime = 60m

Threshold = 1m (Very Small)
├─ Refresh window: 14m - 15m (1 minute)
├─ Risk: May miss refresh window if no requests
├─ Benefit: Tokens stay fresh longer
└─ Use case: Low-traffic applications

Threshold = 5m (Recommended)
├─ Refresh window: 10m - 15m (5 minutes)
├─ Risk: Balanced
├─ Benefit: Good chance of catching refresh
└─ Use case: Most applications

Threshold = 10m (Large)
├─ Refresh window: 5m - 15m (10 minutes)
├─ Risk: Frequent refreshes
├─ Benefit: Almost always refreshed
└─ Use case: High-traffic applications

Threshold = 15m (Same as expiration)
├─ Refresh window: 0m - 15m (entire lifetime)
├─ Risk: Refresh on every request
├─ Benefit: Token always fresh
└─ Use case: Not recommended (performance impact)
```

---

## Summary

### Key Takeaways

1. **LTPA tokens support automatic server-side refresh** based on configurable thresholds
2. **Refresh happens transparently** without user interaction
3. **Max lifetime prevents indefinite refresh** - forces periodic re-authentication
4. **Refresh window is configurable** via `refreshThreshold` parameter
5. **Cookie is automatically updated** when token is refreshed
6. **Original max lifetime is preserved** across refreshes

### Recommended Configuration

```xml
<ltpa 
    expiration="15m"           <!-- Token lifetime -->
    refreshThreshold="5m"      <!-- Refresh 5 min before expiry -->
    maxLifetime="60m"          <!-- Force re-auth after 1 hour -->
/>
```

### Refresh Formula

```
shouldRefresh = (expirationTime - currentTime) ≤ refreshThreshold
                AND
                currentTime < maxLifetimeTime
```

---

**Document Version**: 1.0  
**Last Updated**: 2026-04-15  
**Author**: IBM Liberty Security Team  
**Branch**: ltpa_refresh