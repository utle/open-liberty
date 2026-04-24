# PQC SSL Handshake Testing

## Purpose

Use this skill when you need to design, review, or extend testing for post-quantum cryptography (PQC) in the context of TLS or SSL handshakes, especially in Open Liberty. This skill is intentionally hybrid:

- Open Liberty-focused for contributor workflows, FAT structure, likely code locations, and trace collection
- Broad enough to include external interoperability tools, packet capture, and provider or platform mismatch analysis

This skill is for answering questions such as:

- How should I test PQC or hybrid key exchange during a Liberty TLS handshake?
- What scenarios should be covered in FAT tests versus external interoperability checks?
- How do I tell whether a handshake failed because of cipher selection, trust, certificate constraints, provider support, or protocol negotiation?
- What evidence should I collect to prove PQC behavior rather than generic TLS success?

## Key principle

Do not treat “handshake succeeded” as sufficient evidence of PQC coverage. A successful TLS connection only proves that some mutually acceptable protocol, group, cipher suite, certificate path, and provider combination worked. PQC testing must verify the negotiated mechanism, failure mode, and runtime evidence.

## What to verify in a PQC handshake

For each scenario, verify all of the following where possible:

1. **Protocol result**
   - Example: TLS 1.3 negotiated rather than older fallback behavior
2. **Negotiated cryptographic mechanism**
   - Confirm the expected hybrid or PQC-related group, provider capability, or implementation path
3. **Certificate and trust outcome**
   - Separate key exchange behavior from certificate validation behavior
4. **Runtime evidence**
   - Liberty trace, client output, server logs, packet capture, or provider debug output
5. **Expected failure signature**
   - If negative test, assert the failure reason and not just generic handshake failure
6. **Interoperability boundaries**
   - Verify what works between Liberty, Java clients, and external tooling or providers

## Open Liberty testing surfaces

For Liberty contributors, the likely starting points are:

- SSL implementation and configuration code under [`dev/com.ibm.ws.ssl`](dev/com.ibm.ws.ssl)
- SSL provider wiring such as [`JSSEProvider.java`](dev/com.ibm.ws.ssl/src/com/ibm/websphere/ssl/JSSEProvider.java) and [`AbstractJSSEProvider.java`](dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/provider/AbstractJSSEProvider.java)
- SSL configuration handling such as [`SSLConfigManager.java`](dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/config/SSLConfigManager.java)
- Existing client handshake FAT patterns in [`ClientSSLHandshakeTest.java`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java)
- Existing SSL FAT area in [`dev/io.openliberty.ssl_fat`](dev/io.openliberty.ssl_fat)
- Trace evidence from files such as [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log)

Use these existing areas to avoid inventing a test style that does not fit repository conventions.

## Testing framework choices

### 1. Open Liberty FAT tests

Use FAT when you need repository-native coverage for configuration, server startup, application behavior, or Liberty-managed handshake flows.

Repository conventions from [`AGENTS.md`](AGENTS.md):

- All development code is under [`dev/`](dev/)
- FAT projects end in `_fat`
- FAT tests commonly use [`@RunWith(FATRunner.class)`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java:51)
- Test mode control uses [`@Mode(TestMode.FULL)`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java:52) or LITE where appropriate
- FAT sources live under `fat/src/`
- Build and test commands must run from [`dev/`](dev/)

Use FAT for:

- Liberty server to Java client handshake verification
- Liberty server configuration permutations
- Truststore, keystore, and provider-configuration coverage
- Regression protection for known Liberty SSL behavior
- Assertions based on Liberty logs and process output

### 2. Targeted Java or JSSE-level validation

Use targeted Java tests or helper code when you need to isolate:

- provider availability
- enabled protocol and suite lists
- named group support
- SSLContext or SSLEngine behavior
- differences between raw JSSE capability and Liberty-managed configuration

This is especially useful before building a heavier FAT test.

### 3. External interoperability tooling

Use external tools when Liberty-only evidence is not enough:

- OpenSSL or provider-specific TLS clients and servers
- packet capture tools such as Wireshark or tcpdump
- JDK or provider debug output
- side-by-side provider comparison environments

Use external tools to answer:

- does the peer advertise or accept the expected groups
- is the negotiated path actually hybrid or classical fallback
- is the issue Liberty configuration, Java provider capability, or external incompatibility

## Starter commands and contributor workflow

Follow repository rules from [`AGENTS.md`](AGENTS.md): run build commands from [`dev/`](dev/).

### Initialize build environment if needed

```bash
cd dev && ./gradlew cnf:initialize
```

### Run a single FAT project

```bash
cd dev && ./gradlew com.ibm.ws.security.client_fat:buildandrun
```

If the SSL FAT project is the correct test home, use the same pattern with that project name.

### Narrow investigation to a likely file area

Useful starting locations:

- [`dev/com.ibm.ws.ssl`](dev/com.ibm.ws.ssl)
- [`dev/com.ibm.ws.security.client_fat`](dev/com.ibm.ws.security.client_fat)
- [`dev/io.openliberty.ssl_fat`](dev/io.openliberty.ssl_fat)

### Collect SSL trace evidence

A useful trace pattern is visible in [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log), including:

- `SSLChannel=all`
- `com.ibm.websphere.ssl=all`
- `com.ibm.ws.ssl.*=all`
- `com.ibm.wsspi.ssl.*=all`

That yields trace specifications in the style shown by [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log:11).

## Scenario matrix for PQC SSL handshake testing

The main value of PQC testing is scenario design. Cover both positive and negative cases.

### A. Positive hybrid or PQC-capable handshake

Goal:
- prove that the intended protocol and cryptographic path negotiate successfully

Validate:
- handshake success
- expected protocol version
- expected provider path
- expected runtime evidence showing the intended groups, suites, or provider decisions
- application-level success after handshake

Open Liberty pattern:
- mirror the style of handshake assertions in [`ClientSSLHandshakeTest.java`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java:146)

Do not stop at:
- “server started”
- “client connected”
- generic success code without crypto evidence

### B. No shared algorithm or group

Goal:
- ensure negotiation fails for the correct reason when peer capabilities do not overlap

Examples:
- Liberty side configured for a provider or group the client does not support
- client advertises only classical groups while server requires hybrid-capable negotiation assumptions
- named group or key share mismatch

Validate:
- handshake fails
- failure message is consistent with negotiation incompatibility
- logs do not indicate trust or certificate issues instead

### C. Provider mismatch

Goal:
- separate PQC provider support issues from Liberty configuration issues

Examples:
- Liberty runtime uses one JSSE provider set while the external peer uses another
- provider present but missing expected algorithm enablement
- provider supports TLS 1.3 but not the expected PQC or hybrid mechanism

Validate:
- provider names and runtime selection evidence
- capability mismatch in debug output
- whether fallback occurred silently

The provider initialization path can often be inspected around files such as [`AbstractJSSEProvider.java`](dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/provider/AbstractJSSEProvider.java) and [`JSSEProvider.java`](dev/com.ibm.ws.ssl/src/com/ibm/websphere/ssl/JSSEProvider.java).

### D. Certificate and trust success while PQC negotiation changes

Goal:
- avoid confusing certificate validation with key exchange negotiation

Examples:
- same certificate chain but different key exchange path
- truststore valid, yet handshake fails because negotiated groups do not overlap
- truststore invalid, while PQC capability is otherwise fine

Validate separately:
- trust path result
- hostname verification result
- negotiated handshake mechanism result

A failed trust path is not evidence of PQC failure.

### E. Fallback and downgrade behavior

Goal:
- identify whether a test truly exercised PQC or silently downgraded to classical negotiation

Examples:
- peer supports both classical and hybrid options
- provider chooses a classical path due to ordering or unsupported extension handling
- runtime allows TLS fallback or alternate suite behavior

Validate:
- negotiated final mechanism
- client and server advertised capability sets
- whether fallback is expected or a defect

This is one of the most important PQC-specific checks.

### F. Configuration parsing and enablement errors

Goal:
- ensure configuration mistakes are caught distinctly from protocol failures

Liberty already has examples of configuration-driven handshake outcomes in [`ClientSSLHandshakeTest.java`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java:39), where the test logic distinguishes:

- supported overlap leading to success
- invalid configuration leading to logged errors
- no common cipher leading to handshake failure

Apply the same mindset to PQC testing:
- invalid provider or unsupported option
- malformed configuration
- unsupported combination of protocol and crypto settings

### G. Interoperability matrix

Goal:
- determine supported pairings, not just single-runtime success

Recommended matrix dimensions:

- Liberty server ↔ Java client
- Liberty server ↔ external TLS client
- external TLS server ↔ Liberty client
- same provider on both sides
- mixed providers across peers
- same JDK family across peers
- mixed JDK or provider families across peers

For each matrix cell, record:
- supported
- unsupported by design
- unsupported due to provider limitation
- unsupported due to Liberty defect
- downgraded to classical
- succeeded with expected PQC or hybrid path

### H. Performance and size regressions

Goal:
- capture PQC-related operational cost, not just functional correctness

Measure where practical:
- handshake latency
- CPU increase
- message size increase
- certificate chain or key share size changes
- timeout sensitivity under load

Negative patterns:
- handshake only succeeds with excessive timeout
- repeated retries hide an oversized or slow negotiation path
- flaky FAT behavior due to provider initialization or startup timing

## Evidence collection checklist

Use multiple evidence sources together.

### Liberty logs and trace

Useful evidence includes:

- trace spec lines in [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log:11)
- provider initialization evidence in [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log:33)
- configuration load and SSL manager behavior in [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log:70)

Look for:
- selected provider
- configuration load path
- keystore and truststore initialization
- protocol and SSL context setup
- handshake failure markers
- meaningful error codes rather than generic startup failure only

### FAT assertions

Base FAT assertions on patterns like those used in [`ClientSSLHandshakeTest.java`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java:146):

- assert success for a known-valid overlap
- assert failure for known-invalid negotiation
- assert presence of expected error identifiers
- separate startup readiness from handshake result
- stop and restart test servers cleanly to reduce environmental false positives

### Packet capture and external debug

When the TLS stack or provider supports it, supplement Liberty evidence with:

- packet capture for ClientHello and ServerHello analysis
- provider or JDK TLS debug output
- external peer logs showing selected groups or rejected offers

Be careful not to rely on one source alone.

## How to design a new PQC handshake FAT

1. **Define the exact claim**
   - Example: Liberty should successfully negotiate a hybrid-capable TLS 1.3 handshake with peer X under provider Y
2. **Choose one primary failure axis**
   - provider mismatch
   - no shared group
   - trust failure
   - unsupported config
   - fallback behavior
3. **Hold unrelated variables constant**
   - same certificates
   - same application
   - same transport path
   - only one crypto dimension changed where possible
4. **Create positive and negative twins**
   - one test proving the supported path
   - one test proving a nearby unsupported path fails correctly
5. **Collect at least two forms of evidence**
   - FAT output plus Liberty trace
   - Liberty trace plus external peer debug
6. **Assert the reason, not only the symptom**
   - avoid tests that only prove “something failed”
7. **Record interoperability assumptions**
   - provider version
   - JDK family
   - TLS level
   - peer role and direction
8. **Watch for accidental classical fallback**
   - this is the most common false positive in PQC handshake testing

## Recommended test decomposition

Split tests into layers:

### Layer 1: Capability discovery
- what protocols, suites, groups, and providers are visible

### Layer 2: Configuration validity
- can Liberty parse and initialize the intended settings

### Layer 3: Negotiation result
- does the handshake succeed or fail as intended

### Layer 4: Runtime proof
- do trace or peer logs show the intended crypto path

### Layer 5: Interoperability
- does the same result hold with external peers or alternate providers

### Layer 6: Regression and performance
- are latency, size, and stability still acceptable

This layered model keeps PQC issues diagnosable.

## Common false positives

Do not conclude PQC coverage from any of the following alone:

- handshake succeeded
- server started successfully
- TLS 1.3 was used
- a provider loaded without proving the provider handled the negotiated path
- external tool connected without confirming negotiated parameters
- truststore and certificate validation passed

Each of these can happen even when the runtime fell back to a classical path.

## Common false negatives

Do not misclassify these as PQC defects without evidence:

- wrong truststore or hostname verification
- expired or mismatched certificates
- misconfigured Liberty SSL references
- wrong peer endpoint or port
- server not fully started before test begins
- provider installed but not selected
- environmental timing issues in FAT setup or teardown

The startup and teardown discipline in [`ClientSSLHandshakeTest.java`](dev/com.ibm.ws.security.client_fat/fat/src/com/ibm/ws/security/client/fat/ClientSSLHandshakeTest.java:57) is a good model for reducing this noise.

## Practical workflow for contributors

When asked to test PQC in Liberty SSL handshakes:

1. Inspect likely implementation and test homes:
   - [`dev/com.ibm.ws.ssl`](dev/com.ibm.ws.ssl)
   - [`dev/com.ibm.ws.security.client_fat`](dev/com.ibm.ws.security.client_fat)
   - [`dev/io.openliberty.ssl_fat`](dev/io.openliberty.ssl_fat)
2. Identify whether the question is about:
   - config parsing
   - provider support
   - handshake negotiation
   - interoperability
   - logging or trace evidence
3. Start with the smallest proof:
   - a targeted JSSE or client-server handshake check
4. Promote to FAT when Liberty-managed behavior must be verified
5. Add trace collection similar to the trace style shown in [`ssl_trace.log`](dev/build.image/wlp/usr/servers/defaultServer/logs/ssl_trace.log)
6. Add an external interop check if PQC or hybrid proof cannot be established from Liberty logs alone
7. Document whether the result is:
   - expected success
   - expected failure
   - unsupported combination
   - fallback
   - suspected defect

## Security and policy guardrails

Follow repository security rules:

- do not recommend insecure fallback or disabling certificate validation just to “make PQC tests pass”
- do not bind test services to `0.0.0.0`; use localhost or explicit internal addresses
- do not hardcode secrets or keystore passwords in committed test artifacts
- do not treat self-signed or relaxed validation shortcuts as production guidance
- keep external network calls and tooling use explicit and controlled

If a test requires secrets or certificates, use repository-appropriate test material and environment-controlled inputs.

## Output style this skill should produce

When using this skill, produce answers in this order:

1. testing objective
2. likely Liberty surface or file area
3. recommended framework level
4. scenario matrix
5. evidence to collect
6. concrete commands or starting paths
7. risk of fallback or false interpretation
8. next recommended test or code change

## Reusable checklist

Use this quick checklist before declaring PQC handshake coverage complete:

- [ ] Verified exact protocol version
- [ ] Verified exact negotiated mechanism or provider path
- [ ] Distinguished trust issues from negotiation issues
- [ ] Confirmed no accidental classical fallback
- [ ] Captured Liberty trace or equivalent runtime evidence
- [ ] Added positive and negative scenarios
- [ ] Checked at least one interoperability pairing
- [ ] Considered latency, size, or timeout regressions
- [ ] Recorded environment assumptions such as JDK and provider
- [ ] Aligned the test with existing Liberty FAT conventions

## Example request prompts this skill should handle well

- “Design a FAT plan for PQC or hybrid TLS handshakes between a Liberty server and Java client.”
- “How do I prove a Liberty TLS handshake used the intended hybrid negotiation rather than classical fallback?”
- “What logs and traces should I collect for PQC SSL debugging in Open Liberty?”
- “What interoperability matrix should I run for PQC TLS testing across Liberty and external tools?”
- “Where in the repo should I start if I need to add PQC handshake coverage?”

## Bottom line

For PQC SSL handshake testing, always combine:

- Liberty-native FAT or runtime evidence
- explicit negotiation validation
- negative scenarios that isolate failure cause
- at least one interoperability viewpoint

That combination is what separates real PQC coverage from ordinary TLS connectivity testing.