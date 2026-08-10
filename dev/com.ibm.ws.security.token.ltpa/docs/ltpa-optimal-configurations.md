# LTPA Optimal Configurations

> **Beta feature.** `inactivityTimeout` and `refreshThreshold` are only active when
> Liberty runs in beta mode (`ProductInfo.getBetaEdition() == true`). In GA mode both
> values are forced to `0` and only the hard `expiration` applies.

---

## How the three values interact

```
Login                                                              Hard deadline
  |                                                                     |
  t=0 ─────────────────────────────────────────────────────────────── t=expiration
         │◄─── inactivityTimeout ───►│
         │                  │◄──────►│
         │              refreshThreshold
         │                  │
    WSTOKEN_CREATION_TIME  token refreshed here (new token issued,
    (reset on each refresh) creation time reset, absolute expiry kept)
```

**Key rules enforced by `LTPAToken2`:**

| Rule | Enforcement |
|------|-------------|
| `inactivityTimeout ≤ expiration` | `getInactivityTimeout()` caps the inactivity deadline at `expirationInMilliseconds` |
| `refreshThreshold < inactivityTimeout` | `LTPAConfigurationImpl` auto-corrects to `inactivityTimeout / 3` with warning `CWWKS4123W` |
| Refresh fires when `inactivityTimeRemaining ≤ refreshThreshold` | `checkRefreshNeeded()` sets `triggerRefresh = true` |
| Clone preserves absolute expiry | `clone()` passes `expirationInMilliseconds` to the clone constructor — the hard deadline is never extended |

---

## ASCII Timing Diagrams

### Diagram 1 — Normal session with one refresh

```
Config: expiration=480m, inactivityTimeout=30m, refreshThreshold=10m

t=0         t=20m       t=30m      t=40m       t=60m             t=480m
│           │           │          │           │                  │
├───────────┼───────────│          │           │                  │ (absolute expiry)
│  active   │  idle →   │  would   │           │
│  requests │  20m in   │  expire  │
│           │           │          │
│           │  at t=20m:                token has 10m left in inactivity window
│           │  inactivityTimeRemaining = 10m = refreshThreshold
│           │  ─► triggerRefresh = true
│           │
│           │  new token issued at t=20m:
│           │    WSTOKEN_CREATION_TIME = t=20m   (reset)
│           │    expirationInMilliseconds = t=480m (preserved)
│           │
│                       t=50m (= t=20m + 30m)   ← new inactivity deadline
│                       (capped at t=480m if that would overshoot)
```

### Diagram 2 — Inactivity timeout fires (no refresh configured)

```
Config: expiration=480m, inactivityTimeout=30m, refreshThreshold=0

t=0              t=30m                                           t=480m
│                │                                               │
├────────────────X  TokenExpiredException thrown                 │
│  user goes     │  (inactivity expired)
│  idle at t=0   │
```

### Diagram 3 — Inactivity deadline capped at absolute expiry

```
Config: expiration=25m, inactivityTimeout=30m, refreshThreshold=10m

t=0                       t=25m
│                          │
├──────────────────────────X   absolute expiry (hard cap)
│                          │
│  getInactivityTimeout()  │
│  = min(t=0+30m, t=25m)   │
│  = t=25m  ◄──── capped ──┘

refreshThreshold=10m → refresh fires when ≤10m left before t=25m
i.e. at t=15m
```

### Diagram 4 — Token lifetime with multiple refreshes (active user, all day)

```
Config: expiration=480m, inactivityTimeout=30m, refreshThreshold=10m

 t=0     t=20m    t=40m    t=60m    ...    t=460m  t=470m  t=480m
  │        │        │        │              │        │       │
  ├────────R────────R────────R──── ... ─────R────────X       │ (absolute hard stop)
  │        │        │        │              │  last  │
  │      refresh  refresh  refresh         │ refresh │
  │      (20m in) (20m in) (20m in)        │        │
  │                                        │  at t=470m, inactivity window
  │                                        │  would reach t=500m, but is
  │                                        │  capped at t=480m.
  │                                        │  refreshThreshold check:
  │                                        │  inactivityTimeRemaining = 10m = threshold
  │                                        │  ─► refresh fires, new creationTime = t=470m
  │                                              but expires at t=480m regardless
```

---

## Configuration Patterns

### Pattern 1 — High Security: fixed short window, no sliding

```xml
<ltpa expiration="15" inactivityTimeout="15" refreshThreshold="0"/>
```

| Property            | Value | Effect                                     |
|---------------------|-------|--------------------------------------------|
| `expiration`        | 15m   | Hard wall at `login + 15m`                 |
| `inactivityTimeout` | 15m   | Equal to expiration — no sliding window    |
| `refreshThreshold`  | 0     | No proactive refresh                       |

```
t=0                  t=15m
│                    │
├────────────────────X  hard stop regardless of activity
```

**Use when:** Banking, admin consoles, compliance-mandated re-auth every N minutes.
User must re-authenticate every 15 minutes regardless of activity.

---

### Pattern 2 — Balanced: sliding window with workday hard cap ✅ Most common

```xml
<ltpa expiration="480" inactivityTimeout="30" refreshThreshold="10"/>
```

| Property            | Value      | Effect                                          |
|---------------------|------------|-------------------------------------------------|
| `expiration`        | 480m (8h)  | Hard wall — workday session limit               |
| `inactivityTimeout` | 30m        | Session dies after 30m of inactivity            |
| `refreshThreshold`  | 10m        | Refresh fires when 10m of window remains (≈1/3) |

```
t=0          t=20m       t=50m                              t=480m
│            │           │                                   │
├────────────R───────────┤ idle >30m? expire                │ absolute cap
             │           │
          refresh       next inactivity deadline
          fired         (t=20m + 30m = t=50m)
```

**Use when:** General enterprise web applications.
Active users stay logged in all day (up to 8h). Idle users expire after 30m.

**Rule of thumb:** `refreshThreshold ≈ inactivityTimeout / 3`

---

### Pattern 3 — Long-lived: API clients and dashboards

```xml
<ltpa expiration="1440" inactivityTimeout="60" refreshThreshold="15"/>
```

| Property            | Value       | Effect                                       |
|---------------------|-------------|----------------------------------------------|
| `expiration`        | 1440m (24h) | Absolute wall — one full day                 |
| `inactivityTimeout` | 60m         | Idle sessions expire after 1h                |
| `refreshThreshold`  | 15m         | Refresh at 15m remaining (1/4 of inactivity) |

**Use when:** Internal tooling, dashboards, or APIs where re-auth is disruptive
but idle timeout enforcement is still required.

---

### Pattern 4 — Aggressive refresh: sensitive data, short inactivity

```xml
<ltpa expiration="120" inactivityTimeout="10" refreshThreshold="3"/>
```

| Property            | Value  | Effect                                            |
|---------------------|--------|---------------------------------------------------|
| `expiration`        | 120m   | Hard cap — 2-hour maximum session                 |
| `inactivityTimeout` | 10m    | Tight idle window for sensitive operations        |
| `refreshThreshold`  | 3m     | Refresh with 3m to spare (30% of inactivity)      |

```
t=0      t=7m    t=10m                   t=120m
│        │       │                        │
├────────R───────┤ idle? expire           │ hard cap
         │       │
       refresh  next deadline
       (7m in)  (t=7m + 10m = t=17m)
```

**Use when:** Healthcare portals, sensitive financial reports, or any app where a
short idle window is required but active users must not be interrupted.

---

### Pattern 5 — No inactivity timeout (legacy / GA mode compatible)

```xml
<ltpa expiration="120"/>
```

| Property            | Value  | Effect                                            |
|---------------------|--------|---------------------------------------------------|
| `expiration`        | 120m   | Hard cap — tokens always expire after 2h          |
| `inactivityTimeout` | (none) | Feature disabled — beta guard forces it to 0      |
| `refreshThreshold`  | (none) | Feature disabled — beta guard forces it to 0      |

**Use when:** Environments not running in beta mode, or where sliding window
behaviour is not required. This is the only mode available in GA Liberty releases.

---

## Configuration Decision Flowchart

```
START
  │
  ▼
Running Liberty beta edition?
  │
  ├── NO ──► Use expiration only (Pattern 5).
  │          inactivityTimeout and refreshThreshold are ignored.
  │
  └── YES
        │
        ▼
     Do you need to log idle users out earlier than the hard expiration?
        │
        ├── NO ──► Set inactivityTimeout = expiration (Pattern 1, no sliding window).
        │          Set refreshThreshold = 0 (no proactive refresh).
        │
        └── YES
              │
              ▼
           Is session security critical (banking, healthcare, admin)?
              │
              ├── YES ──► Short inactivityTimeout (≤15m).
              │           refreshThreshold ≈ inactivityTimeout / 3 (Pattern 4).
              │           expiration = maximum acceptable session length.
              │
              └── NO
                    │
                    ▼
                 Long-lived background clients (APIs, dashboards)?
                    │
                    ├── YES ──► expiration = 1440m (24h).
                    │           inactivityTimeout = 60m.
                    │           refreshThreshold = 15m (Pattern 3).
                    │
                    └── NO (general web app)
                          │
                          ▼
                       Use the balanced pattern (Pattern 2):
                         expiration = 480m (8h workday)
                         inactivityTimeout = 30m
                         refreshThreshold = 10m
```

---

## Anti-Patterns to Avoid

| Config                                      | Problem                                                           | Fix                                            |
|---------------------------------------------|-------------------------------------------------------------------|------------------------------------------------|
| `inactivityTimeout > expiration`            | `getInactivityTimeout()` silently caps at `expiration`. Sliding window never starts. | Set `inactivityTimeout < expiration`. |
| `refreshThreshold >= inactivityTimeout`     | Auto-corrected to `inactivityTimeout / 3` with `CWWKS4123W`.     | Set `refreshThreshold < inactivityTimeout`.    |
| `refreshThreshold ≈ expiration` (confused)  | `CWWKS4124W` emitted — threshold is measured against inactivity window, not total lifetime. | Read the warning carefully; set relative to `inactivityTimeout`. |
| `refreshThreshold = 0`                      | No proactive refresh — users hit a hard cutoff with no warning.   | Set a non-zero threshold if using inactivity.  |
| Large `expiration`, no `inactivityTimeout`  | Tokens never expire on idle — security risk for abandoned sessions. | Add `inactivityTimeout`.                      |
| `refreshThreshold` too small (< 1 RTT)      | Refresh may not complete before token expires, causing spurious re-auth. | Use at least 2–3× the round-trip time.       |

---

## Warning Messages Reference

| Message ID     | Trigger condition                                                                               | Auto-correction                     |
|----------------|-------------------------------------------------------------------------------------------------|-------------------------------------|
| `CWWKS4123W`   | `refreshThreshold >= inactivityTimeout` (and `refreshThreshold >= expiration` — clearly wrong) | Adjusted to `inactivityTimeout / 3` |
| `CWWKS4124W`   | `refreshThreshold >= inactivityTimeout` but `refreshThreshold < expiration` (confused with expiration) | Adjusted to `inactivityTimeout / 3` |

Both warnings log the original value, the limit it violated, and the corrected value.

---

## Security Hardening: `expiration`, `inactivityTimeout`, and `refreshThreshold`

These three attributes are your primary controls for limiting the exposure window of a
stolen or abandoned LTPA token. Each one closes a different attack vector.

---

### What each attribute protects against

| Attribute           | Attack it mitigates                                      | How                                                                 |
|---------------------|----------------------------------------------------------|---------------------------------------------------------------------|
| `expiration`        | Stolen token used indefinitely                           | Sets a hard absolute deadline — the token becomes invalid no matter what |
| `inactivityTimeout` | Stolen token from an abandoned/idle session              | Kills the token after a period of inactivity, independent of expiration |
| `refreshThreshold`  | Active user disrupted by sudden expiry at the idle limit | Issues a new token silently before the idle window closes, preserving UX |

No single attribute is sufficient on its own:

- `expiration` alone leaves a wide window for idle-session token theft.
- `inactivityTimeout` alone without `refreshThreshold` abruptly logs out active users when they cross the idle boundary mid-request.
- `refreshThreshold` alone (without `inactivityTimeout`) has no effect — it only fires in relation to the inactivity window.

---

### Hardening matrix

| Security goal                               | `expiration` | `inactivityTimeout`    | `refreshThreshold`              |
|---------------------------------------------|--------------|------------------------|---------------------------------|
| Minimise stolen-token window                | **Low** (15–30m) | Low (= expiration)  | 0 (no refresh needed)           |
| Kill idle sessions without disrupting users | Medium (480m) | **Low** (15–30m)      | **≈ 1/3 of inactivityTimeout**  |
| Balance security and UX for a workday app   | 480m         | 30m                    | 10m                             |
| Tightest possible with active-user UX       | 30m          | 10m                    | 3m                              |

---

### How the three values interact on security

```
Stolen token at time T (e.g. via XSS or network intercept):

  Case A — expiration=480m, no inactivityTimeout
  ─────────────────────────────────────────────
  Attacker can use token for up to 480m from original login.
  Even if the real user has been idle for hours.

  Case B — expiration=480m, inactivityTimeout=30m, no refreshThreshold
  ──────────────────────────────────────────────────────────────────────
  Attacker window = at most 30m from last legitimate request.
  If the real user was idle, token may already be expired.
  Real user sees sudden logout after 30m idle — no warning.

  Case C — expiration=480m, inactivityTimeout=30m, refreshThreshold=10m
  ──────────────────────────────────────────────────────────────────────
  Attacker window = same 30m cap.
  Real user is silently refreshed at 20m idle, resetting the window.
  Active users never see a logout. Idle users expire cleanly at 30m.
  ✅ Best balance of security and usability.
```

---

### Hardening rules (enforced by the implementation)

```
1.  expiration > inactivityTimeout
        If equal, getInactivityTimeout() is always capped at expiration.
        The inactivity window never slides — no benefit from setting it.
        ─► Set inactivityTimeout to LESS than expiration.

2.  inactivityTimeout > refreshThreshold
        If refreshThreshold >= inactivityTimeout, LTPAConfigurationImpl
        auto-corrects to inactivityTimeout / 3 with CWWKS4123W or CWWKS4124W.
        ─► Set refreshThreshold to at most 1/3 of inactivityTimeout.

3.  refreshThreshold >= 1 round-trip time
        If refreshThreshold is too small (< network RTT to complete the
        token refresh), the new token may not arrive before the old one
        expires, causing spurious re-authentication.
        ─► Use at least 1–2 minutes in production.
```

---

### Recommended configs by threat level

**Highest security** — minimise every window:
```xml
<ltpa expiration="30"
      inactivityTimeout="10"
      refreshThreshold="3"/>
```
- Stolen token expires in ≤10m of attacker inactivity (or 30m absolute).
- Active users refreshed every ~7m — fully transparent.

**Standard hardening** — practical for most enterprise web apps:
```xml
<ltpa expiration="480"
      inactivityTimeout="30"
      refreshThreshold="10"/>
```
- Stolen idle token worthless after 30m.
- Active users stay logged in all day (8h cap).

**Minimum viable hardening** — adds inactivity to a legacy config:
```xml
<ltpa expiration="120"
      inactivityTimeout="30"
      refreshThreshold="10"/>
```
- Drop-in addition to a standard 2h token config.
- Cuts the idle theft window from 120m to 30m with no other changes.

---

### Common misconfiguration that weakens security

```xml
<!-- ❌ WRONG — refreshThreshold set relative to expiration, not inactivityTimeout -->
<ltpa expiration="480"
      inactivityTimeout="30"
      refreshThreshold="60"/>
```

`refreshThreshold=60` is larger than `inactivityTimeout=30`. Liberty emits `CWWKS4124W`
and auto-corrects to `10m` (`30 / 3`). The intent was probably to refresh 60m before
the 480m expiration — but that is not what `refreshThreshold` controls.

**Rule:** always think of `refreshThreshold` as a fraction of `inactivityTimeout`,
never relative to `expiration`.

