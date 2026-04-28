# LTPA Keystore Feature - Test Plan

## Overview
This document outlines the testing strategy for the LTPA keystore password resolution fix and the overall LTPA keystore feature.

## Bug Fix Verification

### Test 1: Keystore Configuration with Password
**Objective:** Verify that the password resolution bug is fixed and keystore can be created successfully.

**Configuration:**
```xml
<ltpa keysPassword="{xor}Lz4sLCgwLTs=" 
      keystoreFile="${server.output.dir}/resources/security/ltpa.p12"/>
```

**Expected Results:**
- ✅ Server starts successfully
- ✅ No CWWKS4118E error (password not configured)
- ✅ LTPA keystore file created at specified location
- ✅ CWWKS4104A message shows keystore creation
- ✅ CWWKS4105I message shows LTPA configuration ready

**Test Steps:**
1. Start test server with keystore configuration
2. Check console logs for errors
3. Verify keystore file exists
4. Verify server can create and validate LTPA tokens

---

## Configuration Validation Tests

### Test 2: Both keysFileName and keystoreFile Configured (Should Fail)
**Objective:** Verify mutual exclusivity validation works.

**Configuration:**
```xml
<ltpa keysPassword="{xor}Lz4sLCgwLTs=" 
      keysFileName="${server.output.dir}/resources/security/ltpa.keys"
      keystoreFile="${server.output.dir}/resources/security/ltpa.p12"/>
```

**Expected Results:**
- ❌ Server fails to start
- ✅ CWWKS4120E error message displayed
- ✅ Error message explains only one format can be used

---

### Test 3: Neither keysFileName nor keystoreFile Configured (Should Fail)
**Objective:** Verify that at least one storage format must be specified.

**Configuration:**
```xml
<ltpa keysPassword="{xor}Lz4sLCgwLTs="/>
```

**Expected Results:**
- ❌ Server fails to start
- ✅ CWWKS4121E error message displayed
- ✅ Error message explains one format must be configured

---

### Test 4: Legacy Keys File Configuration (Backward Compatibility)
**Objective:** Verify existing .keys file configurations still work.

**Configuration:**
```xml
<ltpa keysPassword="{xor}Lz4sLCgwLTs=" 
      keysFileName="${server.output.dir}/resources/security/ltpa.keys"/>
```

**Expected Results:**
- ✅ Server starts successfully
- ✅ Legacy .keys file created
- ✅ LTPA tokens work correctly
- ✅ No regression in existing functionality

---

## Functional Tests

### Test 5: Keystore Creation and Token Generation
**Objective:** Verify complete LTPA keystore workflow.

**Test Steps:**
1. Configure server with keystoreFile
2. Start server (keystore should be auto-created)
3. Access protected resource requiring authentication
4. Verify LTPA token is created
5. Verify token can be validated

**Expected Results:**
- ✅ Keystore created with correct format (PKCS12)
- ✅ Keystore contains LTPA keys (private, public, secret)
- ✅ LTPA tokens generated successfully
- ✅ Tokens validated successfully

---

### Test 6: Keystore Password Validation
**Objective:** Verify password is correctly used for keystore operations.

**Test Steps:**
1. Create keystore with password
2. Stop server
3. Restart server (should load existing keystore)
4. Verify keystore loaded successfully

**Expected Results:**
- ✅ Keystore loaded with correct password
- ✅ No password errors
- ✅ Existing keys reused

---

### Test 7: Automatic Conversion from .keys to Keystore
**Objective:** Verify automatic conversion feature works.

**Test Steps:**
1. Start with legacy .keys file configuration
2. Stop server
3. Change configuration to use keystoreFile
4. Restart server

**Expected Results:**
- ✅ Existing .keys file detected
- ✅ Keys automatically converted to keystore format
- ✅ Conversion message logged
- ✅ Original .keys file preserved
- ✅ New keystore created with same keys

---

## Security Tests

### Test 8: Password Security
**Objective:** Verify passwords are handled securely.

**Verification Points:**
- ✅ Passwords not logged in plaintext
- ✅ Passwords masked in trace output
- ✅ Passwords stored securely in keystore
- ✅ No password exposure in error messages

---

### Test 9: Keystore File Permissions
**Objective:** Verify keystore file has appropriate permissions.

**Test Steps:**
1. Create keystore
2. Check file permissions

**Expected Results:**
- ✅ Keystore file readable only by server process owner
- ✅ Appropriate file permissions set (e.g., 600 on Unix)

---

## Integration Tests (FAT)

### Test 10: Run Existing LTPA FAT Tests
**Objective:** Ensure no regressions in existing functionality.

**Command:**
```bash
./gradlew com.ibm.ws.security.token.ltpa_fat:buildandrun
```

**Expected Results:**
- ✅ All existing tests pass
- ✅ No new failures introduced

---

### Test 11: Run New Keystore FAT Tests
**Objective:** Verify new keystore-specific tests pass.

**Test Class:** `LTPAKeystoreTests.java`

**Test Methods:**
1. `testKeystoreCreation()` - Verify keystore auto-creation
2. `testKeystoreLoading()` - Verify loading existing keystore
3. `testKeystoreTokenGeneration()` - Verify token generation with keystore
4. `testKeystoreTokenValidation()` - Verify token validation with keystore
5. `testKeystoreConversion()` - Verify .keys to keystore conversion
6. `testKeystorePasswordChange()` - Verify password change handling
7. `testKeystoreValidationKeys()` - Verify validation keys with keystore

**Expected Results:**
- ✅ All 7 tests pass
- ✅ No compilation errors
- ✅ No runtime errors

---

## Performance Tests

### Test 12: Keystore Performance
**Objective:** Verify keystore operations don't significantly impact performance.

**Metrics to Measure:**
- Server startup time with keystore vs .keys file
- Token generation time
- Token validation time

**Expected Results:**
- ✅ Startup time difference < 5%
- ✅ Token operations performance comparable

---

## Error Handling Tests

### Test 13: Invalid Keystore File
**Objective:** Verify proper error handling for corrupted keystore.

**Test Steps:**
1. Create valid keystore
2. Corrupt keystore file
3. Restart server

**Expected Results:**
- ✅ Appropriate error message
- ✅ Server handles error gracefully
- ✅ Clear guidance in error message

---

### Test 14: Wrong Password
**Objective:** Verify error handling for incorrect password.

**Test Steps:**
1. Create keystore with password A
2. Change configuration to use password B
3. Restart server

**Expected Results:**
- ✅ Password error detected
- ✅ Clear error message
- ✅ Server doesn't start with wrong password

---

## Test Execution Checklist

### Pre-Test Setup
- [ ] Build LTPA module successfully
- [ ] Verify test server configuration
- [ ] Clean previous test artifacts

### Test Execution
- [ ] Run Test 1: Basic keystore configuration
- [ ] Run Test 2: Both formats configured (validation)
- [ ] Run Test 3: Neither format configured (validation)
- [ ] Run Test 4: Legacy .keys file (backward compatibility)
- [ ] Run Test 5: Complete keystore workflow
- [ ] Run Test 6: Password validation
- [ ] Run Test 7: Automatic conversion
- [ ] Run Test 8: Password security
- [ ] Run Test 9: File permissions
- [ ] Run Test 10: Existing FAT tests
- [ ] Run Test 11: New keystore FAT tests
- [ ] Run Test 12: Performance tests
- [ ] Run Test 13: Invalid keystore handling
- [ ] Run Test 14: Wrong password handling

### Post-Test Verification
- [ ] All tests passed
- [ ] No regressions identified
- [ ] Documentation updated
- [ ] Code review completed

---

## Test Results Template

### Test Execution Summary
**Date:** [Date]  
**Tester:** [Name]  
**Build:** [Build Number]  
**Branch:** ltpa_keystore2

| Test # | Test Name | Status | Notes |
|--------|-----------|--------|-------|
| 1 | Keystore with Password | ⏳ | |
| 2 | Both Formats Validation | ⏳ | |
| 3 | Neither Format Validation | ⏳ | |
| 4 | Legacy Keys File | ⏳ | |
| 5 | Complete Workflow | ⏳ | |
| 6 | Password Validation | ⏳ | |
| 7 | Automatic Conversion | ⏳ | |
| 8 | Password Security | ⏳ | |
| 9 | File Permissions | ⏳ | |
| 10 | Existing FAT Tests | ⏳ | |
| 11 | New Keystore FAT Tests | ⏳ | |
| 12 | Performance Tests | ⏳ | |
| 13 | Invalid Keystore | ⏳ | |
| 14 | Wrong Password | ⏳ | |

**Legend:**
- ⏳ Not Started
- 🔄 In Progress
- ✅ Passed
- ❌ Failed
- ⚠️ Blocked

---

## Known Issues and Limitations

### Current Known Issues
1. None identified yet

### Limitations
1. Keystore format is PKCS12 only (by design)
2. Cannot use both .keys and keystore simultaneously (by design)
3. Password must be same for both formats (by design)

---

## Next Steps After Testing

1. **If all tests pass:**
   - Update documentation
   - Prepare for code review
   - Create pull request

2. **If tests fail:**
   - Document failures
   - Investigate root cause
   - Fix issues
   - Re-run tests

3. **Performance concerns:**
   - Profile keystore operations
   - Optimize if needed
   - Document performance characteristics