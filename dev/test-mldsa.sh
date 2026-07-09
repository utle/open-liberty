#!/bin/bash
set -e

echo "=== ML-DSA Complete Test Suite ==="
echo ""

# Test 1: Check ML-DSA availability
echo "Test 1: Checking ML-DSA availability..."
javac TestMLDSASimple.java
java TestMLDSASimple
echo ""

# Test 2: Generate keys
echo "Test 2: Generating ML-DSA keys..."
mkdir -p test-keys
javac GenerateMLDSAKeys.java
java GenerateMLDSAKeys test-keys/audit_signing.pem
echo ""

# Test 3: Test signing
echo "Test 3: Testing ML-DSA signing and verification..."
javac TestMLDSASigning.java
java TestMLDSASigning
echo ""

echo "=== All Tests Complete ==="

# Made with Bob
