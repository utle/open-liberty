#!/bin/bash

#*******************************************************************************
# Copyright (c) 2026 IBM Corporation and others.
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License 2.0
# which accompanies this distribution, and is available at
# http://www.eclipse.org/legal/epl-2.0/
# 
# SPDX-License-Identifier: EPL-2.0
#
# Contributors:
#     IBM Corporation - initial API and implementation
#*******************************************************************************

# Audit Performance Comparison Script
# Compares audit log performance with PQC disabled vs enabled

set -e

# Configuration
SERVER_DIR="/Users/niyathar/libertyGit/open-liberty/dev/build.image/wlp"
SERVER_NAME="defaultServer"
JAVA_HOME="${JAVA_HOME:-/Users/niyathar/Downloads/jdk26/Contents/Home}"
EVENT_COUNT=100
SERVER_URL="https://localhost:9443"

# Output directories (use absolute paths)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/audit-comparison-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_DIR="${RESULTS_DIR}/${TIMESTAMP}"

echo "========================================="
echo "Audit Performance Comparison Tool"
echo "========================================="
echo ""

# Create results directory
mkdir -p "${RUN_DIR}"

# Function to stop server
stop_server() {
    echo "Stopping server..."
    cd "${SERVER_DIR}/bin"
    ./server stop ${SERVER_NAME} || true
    sleep 5
}

# Function to start server with specific JVM options
start_server() {
    local pqc_enabled=$1
    echo "Starting server with PQC ${pqc_enabled}..."
    
    # Update jvm.options
    local jvm_options="${SERVER_DIR}/usr/servers/${SERVER_NAME}/jvm.options"
    
    # Backup original jvm.options
    if [ ! -f "${jvm_options}.backup" ]; then
        cp "${jvm_options}" "${jvm_options}.backup" 2>/dev/null || true
    fi
    
    # Create new jvm.options
    cat > "${jvm_options}" << EOF
-Dcom.ibm.ws.security.pqc.enabled=${pqc_enabled}
-Xmx512m
EOF
    
    cd "${SERVER_DIR}/bin"
    ./server start ${SERVER_NAME}
    
    # Wait for server to be ready
    echo "Waiting for server to start..."
    sleep 10
    
    # Check if server is ready
    local max_attempts=30
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if curl -k -s "${SERVER_URL}" > /dev/null 2>&1; then
            echo "Server is ready!"
            return 0
        fi
        echo "Waiting for server... (attempt $((attempt+1))/${max_attempts})"
        sleep 2
        attempt=$((attempt+1))
    done
    
    echo "ERROR: Server failed to start"
    return 1
}

# Function to clear audit logs
clear_audit_logs() {
    echo "Clearing audit logs..."
    local logs_dir="${SERVER_DIR}/usr/servers/${SERVER_NAME}/logs"
    rm -f "${logs_dir}/audit.log" "${logs_dir}/audit-output.log" 2>/dev/null || true
}

# Function to decrypt audit log
decrypt_audit_log() {
    local encrypted_log=$1
    local decrypted_log=$2
    local pqc_enabled=$3
    
    echo "Decrypting audit log (PQC: ${pqc_enabled})..."
    
    # Convert to absolute paths
    decrypted_log=$(cd "$(dirname "${decrypted_log}")" 2>/dev/null && pwd)/$(basename "${decrypted_log}") || echo "${decrypted_log}"
    
    # Ensure output directory exists
    local output_dir=$(dirname "${decrypted_log}")
    mkdir -p "${output_dir}"
    
    local utility_log="${decrypted_log}.utility.log"
    
    cd "${SERVER_DIR}/bin"
    
    # Determine which keystores to use based on PQC setting
    local enc_keystore
    local signing_keystore
    local enc_password
    local signing_password
    
    if [ "${pqc_enabled}" = "true" ]; then
        # Use PQC keystores (ML-KEM/ML-DSA keys)
        enc_keystore="${SERVER_DIR}/usr/servers/${SERVER_NAME}/resources/security/AuditEncryptionKeyStore.p12"
        signing_keystore="${SERVER_DIR}/usr/servers/${SERVER_NAME}/resources/security/AuditSigningKeyStore.p12"
        enc_password="Liberty"
        signing_password="Liberty"
        echo "Using PQC keystores (ML-KEM/ML-DSA keys)"
    else
        # Use RSA keystores
        enc_keystore="${SERVER_DIR}/usr/servers/${SERVER_NAME}/resources/security/rsa-encryption.p12"
        signing_keystore="${SERVER_DIR}/usr/servers/${SERVER_NAME}/resources/security/rsa-signing.p12"
        enc_password="changeit"
        signing_password="changeit"
        echo "Using RSA keystores"
        
        # Verify RSA keystores exist
        if [ ! -f "${enc_keystore}" ]; then
            echo "ERROR: RSA encryption keystore not found at ${enc_keystore}"
            return 1
        fi
        if [ ! -f "${signing_keystore}" ]; then
            echo "ERROR: RSA signing keystore not found at ${signing_keystore}"
            return 1
        fi
    fi
    
    JAVA_HOME="${JAVA_HOME}" ./auditUtility auditReader \
        --auditFileLocation="${encrypted_log}" \
        --outputFileLocation="${decrypted_log}" \
        --encrypted=true \
        --encKeyStoreLocation="${enc_keystore}" \
        --encKeyStorePassword="${enc_password}" \
        --encKeyStoreType=PKCS12 \
        --signed=true \
        --signingKeyStoreLocation="${signing_keystore}" \
        --signingKeyStorePassword="${signing_password}" \
        --signingKeyStoreType=PKCS12 \
        > "${utility_log}" 2>&1
    
    if [ ! -f "${decrypted_log}" ]; then
        echo "ERROR: Failed to decrypt audit log"
        cat "${utility_log}"
        return 1
    fi
    
    echo "Audit log decrypted successfully"
}

# Function to run audit event trigger
run_audit_trigger() {
    echo "Generating ${EVENT_COUNT} audit events..."
    cd /Users/niyathar/libertyGit/open-liberty/dev
    
    java AuditEventTrigger.java \
        --url "${SERVER_URL}" \
        --count ${EVENT_COUNT} 2>&1 | grep -v "warning:"
}

# Function to run comparison for one mode
run_test() {
    local mode=$1
    local pqc_value=$2
    
    echo ""
    echo "========================================="
    echo "Running test: ${mode}"
    echo "========================================="
    
    # Stop server
    stop_server
    
    # Clear logs
    clear_audit_logs
    
    # Start server with specific PQC setting
    local server_start_time=$(date +%s)
    start_server "${pqc_value}"
    local server_ready_time=$(date +%s)
    local server_startup_duration=$((server_ready_time - server_start_time))
    
    echo "Server startup took ${server_startup_duration} seconds"
    
    # Run audit trigger and measure client-side time
    echo "Generating ${EVENT_COUNT} audit events..."
    local trigger_start_time=$(date +%s%N)  # nanoseconds for better precision
    run_audit_trigger
    local trigger_end_time=$(date +%s%N)
    local trigger_duration_ns=$((trigger_end_time - trigger_start_time))
    local trigger_duration_ms=$((trigger_duration_ns / 1000000))
    
    echo "Client-side request time: ${trigger_duration_ms}ms"
    
    # Wait a moment for server to finish writing audit logs
    sleep 2
    
    # Copy and decrypt audit log
    local logs_dir="${SERVER_DIR}/usr/servers/${SERVER_NAME}/logs"
    local encrypted_log="${logs_dir}/audit.log"
    local decrypted_log="${RUN_DIR}/audit-${mode}.log"
    
    if [ -f "${encrypted_log}" ]; then
        cp "${encrypted_log}" "${RUN_DIR}/audit-${mode}-encrypted.log"
        
        # Measure decryption time
        local decrypt_start_time=$(date +%s%N)
        decrypt_audit_log "${encrypted_log}" "${decrypted_log}" "${pqc_value}"
        local decrypt_end_time=$(date +%s%N)
        local decrypt_duration_ns=$((decrypt_end_time - decrypt_start_time))
        local decrypt_duration_ms=$((decrypt_duration_ns / 1000000))
        
        echo "Decryption time: ${decrypt_duration_ms}ms"
        
        # Save detailed timing info
        cat > "${RUN_DIR}/timing-${mode}.txt" << EOF
Server Startup: ${server_startup_duration}s
Client Request Time: ${trigger_duration_ms}ms
Decryption Time: ${decrypt_duration_ms}ms
EOF
    else
        echo "WARNING: No audit log found at ${encrypted_log}"
        echo "Checking for audit logs in other locations..."
        find "${SERVER_DIR}/usr/servers/${SERVER_NAME}" -name "audit.log" -type f
    fi
}

# Main execution
echo "Results will be saved to: ${RUN_DIR}"
echo ""

# Run test with PQC disabled
run_test "nopqc" "false"

# Run test with PQC enabled
run_test "pqc" "true"

# Stop server
stop_server

# Restore original jvm.options
jvm_options="${SERVER_DIR}/usr/servers/${SERVER_NAME}/jvm.options"
if [ -f "${jvm_options}.backup" ]; then
    mv "${jvm_options}.backup" "${jvm_options}"
fi

# Generate HTML comparison report
echo ""
echo "========================================="
echo "Generating HTML comparison report..."
echo "========================================="

cd /Users/niyathar/libertyGit/open-liberty/dev

if [ -f "${RUN_DIR}/audit-nopqc.log" ] && [ -f "${RUN_DIR}/audit-pqc.log" ]; then
    java AuditComparisonTool.java \
        "${RUN_DIR}/audit-nopqc.log" \
        "${RUN_DIR}/audit-pqc.log" \
        "${RUN_DIR}/comparison-report.html"
    
    echo ""
    echo "========================================="
    echo "Comparison Complete!"
    echo "========================================="
    echo ""
    echo "Results saved to: ${RUN_DIR}"
    echo ""
    echo "Files generated:"
    echo "  - audit-nopqc.log           : Decrypted audit log (PQC disabled)"
    echo "  - audit-pqc.log             : Decrypted audit log (PQC enabled)"
    echo "  - comparison-report.html    : HTML comparison report"
    echo "  - timing-*.txt              : Timing information"
    echo ""
    echo "Open the HTML report:"
    echo "  open ${RUN_DIR}/comparison-report.html"
    echo ""
else
    echo "ERROR: Could not find decrypted audit logs"
    echo "Available files in ${RUN_DIR}:"
    ls -la "${RUN_DIR}"
fi

# Made with Bob
