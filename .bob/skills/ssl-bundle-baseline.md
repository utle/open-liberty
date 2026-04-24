# SSL Bundle Baseline Understanding

## Purpose

Use this skill when you need to understand how SSL bundles work in Open Liberty. This skill provides comprehensive understanding of the SSL architecture, configuration, runtime behavior, and handshake process.

This skill answers questions such as:

- How does the SSL bundle architecture work in Open Liberty?
- What are the key components and their responsibilities?
- How does SSL configuration flow from server.xml to runtime SSL contexts?
- What is the relationship between keystores, SSL configurations, and JSSE providers?
- How does the SSL handshake process work?
- How should I trace and debug SSL behavior?
- What are the extension points for adding new cryptographic capabilities?

## Key Principle

The SSL bundle provides the foundation for all TLS/SSL operations in Liberty. Understanding this architecture is essential for any SSL-related development, debugging, or enhancement work.

## SSL Bundle Architecture Overview

The SSL bundle (com.ibm.ws.ssl) is an OSGi bundle that provides SSL configuration and runtime support for Open Liberty. It is designed to be provider-agnostic while supporting multiple JSSE implementations.

### Core Design Principles

1. **Provider Abstraction**: The bundle abstracts JSSE provider details through the JSSEProvider interface
2. **Configuration Management**: Centralized SSL configuration through SSLConfigManager
3. **Keystore Lifecycle**: Managed keystore loading and monitoring
4. **OSGi Integration**: Declarative Services for component lifecycle and configuration updates
5. **Backward Compatibility**: Support for multiple TLS versions and cipher suites

## Key Components and Their Roles

### 1. SSLComponent

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/internal/SSLComponent.java

**Role**: OSGi Declarative Services component that manages the SSL bundle lifecycle

**Key Responsibilities**:
- Activates and deactivates the SSL subsystem
- Manages SSL repertoire configurations (multiple SSL configs)
- Coordinates keystore references
- Integrates with Liberty's feature provisioner
- Handles configuration updates dynamically

**Configuration PID**: com.ibm.ws.ssl.default

### 2. SSLConfigManager

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/config/SSLConfigManager.java

**Role**: Singleton manager for all SSL configurations in the runtime

**Key Responsibilities**:
- Maintains map of SSL configuration objects (sslConfigMap)
- Manages SSL configuration change listeners
- Handles outbound SSL selections
- Provides global SSL properties
- Coordinates protocol and cipher suite selection

### 3. JSSEProvider Interface

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/websphere/ssl/JSSEProvider.java

**Role**: Provider abstraction interface for JSSE implementations

**Key Methods**:
- getSSLProtocolPackageHandler(): Returns HTTPS protocol handler package
- getDefaultProtocol(): Returns default SSL/TLS protocol
- getCiphersForSecurityLevel(): Returns cipher suites for security level
- getSSLContextInstance(): Creates SSLContext from configuration
- getSSLContext(): Creates SSLContext with connection info

**Purpose**: Allows Liberty to work with different JSSE providers without provider-specific code

### 4. AbstractJSSEProvider

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/provider/AbstractJSSEProvider.java

**Role**: Abstract base class implementing common JSSE provider functionality

**Key Responsibilities**:
- SSLContext caching
- KeyManager and TrustManager factory creation
- Keystore loading and initialization
- Protocol handler initialization
- Provider-specific customization points

### 5. KeyStore Management

**Key Classes**:
- KeyStoreManager: Manages keystore lifecycle
- WSKeyStore: Wrapper for Java KeyStore with Liberty-specific features
- KeystoreConfig: Configuration object for keystores
- KeystoreConfigurationFactory: Factory for creating keystore configurations

## Configuration Flow

### From server.xml to Runtime

1. **Server Configuration** (server.xml)
2. **OSGi Configuration Admin**: Converts XML to configuration dictionaries
3. **SSLComponent Activation**: Initializes SSL subsystem
4. **SSLConfig Creation**: Configuration properties converted to SSLConfig object
5. **Keystore Resolution**: Keystore references resolved to WSKeyStore objects
6. **SSLContext Creation**: SSLContext created with configured protocol and ciphers

## SSL Handshake Process

### Handshake Components

The SSL handshake in Liberty involves several key components working together:

#### 1. WSSocket

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/config/WSSocket.java

**Role**: Wrapper around SSLSocket that provides Liberty-specific functionality

**Key Handshake Methods**:
- startHandshake(): Initiates the SSL handshake
- addHandshakeCompletedListener(): Registers listeners for handshake completion
- removeHandshakeCompletedListener(): Removes handshake completion listeners
- getSession(): Returns the SSLSession after handshake completes

**Purpose**: Provides a consistent interface for SSL socket operations while delegating to the underlying SSLSocket implementation

#### 2. LibertySSLEngineWrapper

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/LibertySSLEngineWrapper.java

**Role**: Wrapper for SSLEngine that applies Liberty SSL configuration

**Key Handshake Methods**:
- beginHandshake(): Initiates handshake for SSLEngine-based connections
- getHandshakeStatus(): Returns current handshake status
- wrap(): Wraps application data during handshake
- unwrap(): Unwraps network data during handshake

**Configuration Application**:
- Sets enabled cipher suites from Liberty configuration
- Sets enabled protocols from Liberty configuration
- Applies configuration before handshake begins

**Purpose**: Ensures Liberty's SSL configuration is applied to SSLEngine-based connections (used by non-blocking I/O)

#### 3. WSX509TrustManager

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/core/WSX509TrustManager.java

**Role**: Custom TrustManager that validates certificates during handshake

**Key Handshake Responsibilities**:
- Validates server certificates during client handshake
- Validates client certificates during server handshake (mutual TLS)
- Performs hostname verification
- Checks certificate expiration and validity
- Verifies certificate chain trust

**Handshake Error Handling**:
- printClientHandshakeError(): Logs detailed handshake errors
- Provides specific error messages for different failure types
- Uses getHandshakeSession() to access peer information during validation

**Purpose**: Provides certificate validation and trust verification during the SSL handshake

#### 4. WSX509KeyManager

**Location**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/core/WSX509KeyManager.java

**Role**: Custom KeyManager that selects client certificates during handshake

**Key Handshake Methods**:
- chooseClientAlias(): Selects client certificate for handshake
- chooseServerAlias(): Selects server certificate for handshake
- chooseEngineClientAlias(): Selects client certificate for SSLEngine handshake
- chooseEngineServerAlias(): Selects server certificate for SSLEngine handshake

**Purpose**: Manages certificate selection from keystores during the handshake process

### Handshake Flow

#### Client-Side Handshake

1. **Initiation**: Application calls connect() or startHandshake()
2. **Configuration**: LibertySSLEngineWrapper applies enabled protocols and ciphers
3. **ClientHello**: Client sends supported protocols, cipher suites, and extensions
4. **Certificate Validation**: WSX509TrustManager validates server certificate
5. **Key Exchange**: Client and server exchange key material
6. **Finished**: Handshake completes, SSLSession established
7. **Listeners Notified**: HandshakeCompletedListeners are invoked

#### Server-Side Handshake

1. **Accept**: Server accepts incoming SSL connection
2. **Configuration**: LibertySSLEngineWrapper applies enabled protocols and ciphers
3. **ServerHello**: Server selects protocol and cipher suite
4. **Certificate Selection**: WSX509KeyManager selects server certificate
5. **Client Certificate Request** (if mutual TLS): Server requests client certificate
6. **Client Certificate Validation** (if mutual TLS): WSX509TrustManager validates client certificate
7. **Key Exchange**: Server and client exchange key material
8. **Finished**: Handshake completes, SSLSession established

### Handshake Session Information

After successful handshake, the SSLSession provides:
- Negotiated protocol version (e.g., TLSv1.3)
- Negotiated cipher suite
- Peer certificates
- Session ID for resumption
- Creation time and last accessed time

## Extension Points

Understanding these extension points is critical for adding new capabilities:

### 1. Protocol Selection

**Current**: JSSEProvider.getDefaultProtocol() returns "TLS" or "SSL"
**Extension**: Can be extended to support new protocol versions or modes

### 2. Cipher Suite Selection

**Current**: JSSEProvider.getCiphersForSecurityLevel() returns cipher suites
**Extension**: Can be extended to include new cipher suites

### 3. SSLContext Creation

**Current**: AbstractJSSEProvider.getSSLContext() creates standard SSLContext
**Extension**: Can be customized for specialized SSLContext initialization

### 4. Certificate Validation

**Current**: WSX509TrustManager performs standard certificate validation
**Extension**: Can be extended for custom validation logic

### 5. Configuration Properties

**Current**: Standard SSL configuration properties
**Extension**: Can be extended with new properties for specialized features

## Tracing and Debugging

### Trace Specifications

*=info:SSLChannel=all:com.ibm.websphere.ssl=all:com.ibm.ws.ssl.*=all:com.ibm.wsspi.ssl.*=all

**Key Trace Groups**:
- SSLChannel: SSL channel operations
- com.ibm.websphere.ssl: Public SSL API
- com.ibm.ws.ssl.*: Internal SSL implementation
- com.ibm.wsspi.ssl.*: SSL SPI

### Handshake Tracing

To trace handshake behavior:
1. Enable SSL trace as shown above
2. Look for handshake initiation messages
3. Check certificate validation messages
4. Verify protocol and cipher negotiation
5. Check for handshake completion or failure

### Common Handshake Issues

**Certificate Validation Failures**:
- Check WSX509TrustManager trace for validation errors
- Verify truststore contains required CA certificates
- Check certificate expiration dates

**Protocol Negotiation Failures**:
- Verify enabled protocols on both client and server
- Check for protocol version mismatches
- Review LibertySSLEngineWrapper configuration

**Cipher Suite Mismatches**:
- Verify enabled cipher suites on both sides
- Check for common cipher suites
- Review security level settings

## Testing Baseline SSL

### Existing Test Locations

- **SSL FAT Tests**: dev/io.openliberty.ssl_fat
- **Client SSL Tests**: dev/com.ibm.ws.security.client_fat
- **Example Test**: dev/io.openliberty.ssl_fat/fat/src/io/openliberty/ssl/fat/CipherModifierTest.java

### Test Patterns

1. **Configuration Tests**: Verify SSL configuration parsing and application
2. **Handshake Tests**: Test successful and failed handshakes
3. **Certificate Tests**: Test certificate validation and selection
4. **Protocol Tests**: Test different TLS protocol versions
5. **Cipher Tests**: Test cipher suite selection and negotiation

## File Locations Reference

### Core Implementation

- **Bundle Definition**: dev/com.ibm.ws.ssl/bnd.bnd
- **Component**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/internal/SSLComponent.java
- **Config Manager**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/config/SSLConfigManager.java
- **Provider Interface**: dev/com.ibm.ws.ssl/src/com/ibm/websphere/ssl/JSSEProvider.java
- **Provider Base**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/provider/AbstractJSSEProvider.java

### Handshake Implementation

- **Socket Wrapper**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/config/WSSocket.java
- **Engine Wrapper**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/LibertySSLEngineWrapper.java
- **Trust Manager**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/core/WSX509TrustManager.java
- **Key Manager**: dev/com.ibm.ws.ssl/src/com/ibm/ws/ssl/core/WSX509KeyManager.java

## Bottom Line

The SSL bundle provides a well-architected foundation for TLS/SSL in Open Liberty with:
- Provider-agnostic design through JSSEProvider interface
- Centralized configuration through SSLConfigManager
- Comprehensive handshake support via WSSocket and LibertySSLEngineWrapper
- Robust certificate validation through WSX509TrustManager
- OSGi integration for dynamic lifecycle management
- Extensible architecture for adding new capabilities

Understanding this architecture is essential for any SSL-related work in Open Liberty.
