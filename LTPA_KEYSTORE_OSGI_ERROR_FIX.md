# LTPA Keystore OSGi Error Fix

## Error Description

```
[ERROR] CWWKE0701E: bundle com.ibm.ws.security.token.ltpa:1.0.113.202604231431 (143)
[com.ibm.ws.security.token.ltpa.internal.LTPAConfigurationImpl(413)] : 
unbind method [unsetKeyStoreService] not found; Component will fail
```

## Root Cause

This error occurs because a previous incomplete implementation (commit c75ba0576cb) added a `KeyStoreService` reference to the OSGi component configuration in `bnd.bnd`:

```
keyStoreService=com.ibm.ws.ssl.KeyStoreService; \
optional:='keyStoreService'; \
```

This reference was reverted in commit 2a71547b8af, but:
1. The Liberty runtime is using a cached/old JAR file
2. The old JAR contains OSGi metadata expecting `setKeyStoreService` and `unsetKeyStoreService` methods
3. These methods don't exist in `LTPAConfigurationImpl.java`

## Verification

The current source code is correct:
- ✅ `bnd.bnd` does NOT have KeyStoreService reference
- ✅ `LTPAConfigurationImpl.java` does NOT have KeyStoreService methods
- ✅ New implementation uses `LTPAKeystoreManager` directly (no OSGi service dependency)

The issue is with deployed/cached artifacts, not the source code.

## Solution

### Option 1: Clean Build (Recommended)

```bash
# Set Java environment
export JAVA_HOME=/path/to/java17
export JAVA_21_HOME=/path/to/java21

# Clean and rebuild
cd dev
./gradlew com.ibm.ws.security.token.ltpa:clean
./gradlew com.ibm.ws.security.token.ltpa:build

# Verify the JAR doesn't have KeyStoreService
unzip -p com.ibm.ws.security.token.ltpa/build/libs/com.ibm.ws.security.token.ltpa.jar \
  OSGI-INF/com.ibm.ws.security.token.ltpa.LTPAConfiguration.xml | grep -i keystore
# Should return nothing
```

### Option 2: Clean Liberty Installation

If the error persists after rebuilding:

```bash
# Stop Liberty server
cd dev/build.image/wlp/bin
./server stop testLTPAKeystore

# Remove cached bundles
rm -rf ../usr/servers/testLTPAKeystore/workarea

# Remove old LTPA bundle from Liberty
rm -f ../lib/com.ibm.ws.security.token.ltpa*.jar

# Rebuild and reinstall
cd ../../../../dev
./gradlew com.ibm.ws.security.token.ltpa:clean
./gradlew com.ibm.ws.security.token.ltpa:build
./gradlew assemble

# Start server with fresh bundle
cd build.image/wlp/bin
./server start testLTPAKeystore
```

### Option 3: Full Clean Build

For a complete clean slate:

```bash
cd dev
./gradlew clean
./gradlew cnf:initialize
./gradlew assemble
```

## Expected Result After Fix

After cleaning and rebuilding, the server should start without errors:

```
[AUDIT] CWWKS4103I: Creating the LTPA keys. This may take a few seconds.
[AUDIT] CWWKS4122A: LTPA keystore created in 2 seconds. LTPA keystore file: .../ltpa.p12
[INFO ] CWWKS4105I: LTPA configuration is ready after 3 seconds.
```

## Why This Happened

1. **Initial Implementation (c75ba0576cb):** Added KeyStoreService dependency
   - Added `keyStoreService` reference in bnd.bnd
   - OSGi expected `setKeyStoreService` and `unsetKeyStoreService` methods
   - Implementation was incomplete

2. **Revert (2a71547b8af):** Removed KeyStoreService from bnd.bnd
   - Source code correctly reverted
   - But old JAR remained in Liberty installation

3. **New Implementation:** Uses LTPAKeystoreManager directly
   - No OSGi service dependency
   - Self-contained keystore operations
   - Clean, simple design

## Prevention

To avoid this issue in the future:

1. **Always clean build after reverting commits:**
   ```bash
   ./gradlew com.ibm.ws.security.token.ltpa:clean
   ./gradlew com.ibm.ws.security.token.ltpa:build
   ```

2. **Clear Liberty workarea when testing:**
   ```bash
   rm -rf wlp/usr/servers/*/workarea
   ```

3. **Verify OSGi metadata after changes:**
   ```bash
   unzip -p build/libs/*.jar OSGI-INF/*.xml | grep -i "reference name"
   ```

## Technical Details

### OSGi Declarative Services

OSGi DS uses XML descriptors generated from bnd.bnd:
- `bnd.bnd` defines service references
- Bnd tool generates `OSGI-INF/*.xml` files
- OSGi runtime expects matching bind/unbind methods

### Our Implementation

We intentionally avoid OSGi service dependencies:
- **Old approach:** Depend on `com.ibm.ws.ssl.KeyStoreService`
- **New approach:** Use `LTPAKeystoreManager` directly
- **Benefit:** Simpler, more maintainable, fewer dependencies

### Keystore Operations

```java
// Direct keystore operations (no OSGi service)
LTPAKeystoreManager manager = new LTPAKeystoreManager();
manager.createKeystore(file, password, ltpaKeys);
LTPAKeys keys = manager.loadKeysFromKeystore(file, password);
```

## Verification Checklist

After applying the fix, verify:

- [ ] No CWWKE0701E errors in messages.log
- [ ] Server starts successfully
- [ ] LTPA keystore created (if useKeystore="true")
- [ ] LTPA configuration ready message appears
- [ ] No FFDC files generated
- [ ] OSGi component XML has no KeyStoreService reference

## Related Files

- `dev/com.ibm.ws.security.token.ltpa/bnd.bnd` - OSGi component configuration
- `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAConfigurationImpl.java` - Component implementation
- `dev/com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeystoreManager.java` - Keystore operations

## Summary

The error is caused by stale OSGi metadata in cached JAR files, not by the current source code. A clean build will resolve the issue. The new implementation correctly uses `LTPAKeystoreManager` directly without OSGi service dependencies.