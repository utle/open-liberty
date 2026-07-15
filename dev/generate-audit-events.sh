#!/bin/bash
################################################################################
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
################################################################################

# Script to easily generate audit events for Open Liberty testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="${SCRIPT_DIR}/../build.image/wlp/usr/servers/defaultServer"
AUDIT_LOG="${SERVER_DIR}/logs/audit.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Generate audit events for Open Liberty testing"
    echo ""
    echo "Options:"
    echo "  -c, --count <number>      Generate specified number of events (default: 5000)"
    echo "  -d, --duration <seconds>  Generate events for specified duration"
    echo "  -r, --rate <events/sec>   Events per second for duration mode (default: 10)"
    echo "  -o, --output <file>       Output file (default: server's audit.log)"
    echo "  -s, --stop-server         Stop server before generating (recommended)"
    echo "  -h, --help                Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --count 5000                    # Generate 5000 events"
    echo "  $0 --duration 600 --rate 20        # Generate for 10 minutes at 20/sec"
    echo "  $0 --count 10000 --stop-server     # Stop server, generate 10000 events"
}

# Default values
COUNT=5000
DURATION=""
RATE=10
OUTPUT="${AUDIT_LOG}"
STOP_SERVER=false
USE_DURATION=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--count)
            COUNT="$2"
            USE_DURATION=false
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            USE_DURATION=true
            shift 2
            ;;
        -r|--rate)
            RATE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -s|--stop-server)
            STOP_SERVER=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option $1${NC}"
            print_usage
            exit 1
            ;;
    esac
done

# Compile if needed
if [ ! -f "${SCRIPT_DIR}/AuditEventGenerator.class" ]; then
    echo -e "${YELLOW}Compiling AuditEventGenerator...${NC}"
    javac "${SCRIPT_DIR}/AuditEventGenerator.java"
    echo -e "${GREEN}Compilation complete${NC}"
fi

# Stop server if requested
if [ "$STOP_SERVER" = true ]; then
    echo -e "${YELLOW}Stopping server...${NC}"
    if [ -f "${SCRIPT_DIR}/../build.image/wlp/bin/server" ]; then
        "${SCRIPT_DIR}/../build.image/wlp/bin/server" stop defaultServer || true
        sleep 2
        echo -e "${GREEN}Server stopped${NC}"
    else
        echo -e "${YELLOW}Warning: Server script not found, skipping stop${NC}"
    fi
fi

# Generate events
echo -e "${GREEN}Generating audit events...${NC}"
cd "${SCRIPT_DIR}"

if [ "$USE_DURATION" = true ]; then
    java AuditEventGenerator --output "${OUTPUT}" --duration "${DURATION}" --rate "${RATE}"
else
    java AuditEventGenerator --output "${OUTPUT}" --count "${COUNT}"
fi

echo ""
echo -e "${GREEN}✓ Audit events generated successfully!${NC}"
echo -e "Output file: ${OUTPUT}"
echo ""

if [ "$OUTPUT" = "$AUDIT_LOG" ]; then
    echo -e "${YELLOW}Note: Events were written to the server's audit log.${NC}"
    echo -e "Start your server to see the audit events:"
    echo -e "  ${SCRIPT_DIR}/../build.image/wlp/bin/server start defaultServer"
fi

# Made with Bob
