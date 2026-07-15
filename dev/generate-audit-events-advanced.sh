#!/bin/bash

# Advanced Audit Event Generator Script for Open Liberty
# Supports plain, encrypted, and signed audit event generation

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_XML="${SCRIPT_DIR}/build.image/wlp/usr/servers/defaultServer/server.xml"
AUDIT_TRIGGER="${SCRIPT_DIR}/AuditEventTrigger.class"
JAVA_SOURCE="${SCRIPT_DIR}/AuditEventTrigger.java"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Advanced Audit Event Generator for Open Liberty

OPTIONS:
    -m, --mode MODE         Audit mode: plain, encrypted, signed, or both (default: plain)
                           - plain: Standard audit events (no encryption/signing)
                           - encrypted: Encrypted audit events only
                           - signed: Signed audit events only
                           - both: Both encrypted and signed audit events
    
    -c, --count COUNT      Number of audit events to generate (default: 1000)
    -d, --duration SECONDS Duration in seconds to generate events (overrides count)
    -r, --rate RATE        Events per second (default: 20)
    -u, --url URL          Server URL (default: http://localhost:9080)
    
    --no-restart           Don't restart the server (use if already configured)
    --compile              Force recompile of AuditEventTrigger.java
    -h, --help             Display this help message

EXAMPLES:
    # Generate 5000 plain audit events
    $0 --mode plain --count 5000

    # Generate encrypted and signed events for 10 minutes
    $0 --mode both --duration 600

    # Generate signed events at 50 events/second
    $0 --mode signed --count 10000 --rate 50

    # Generate encrypted events without restarting server
    $0 --mode encrypted --count 2000 --no-restart

NOTES:
    - The script will automatically configure server.xml based on the mode
    - Server restart is required when changing audit modes (unless --no-restart is used)
    - Keystores must exist at:
      * resources/security/AuditEncryptionKeyStore.p12 (for encryption)
      * resources/security/AuditSigningKeyStore.p12 (for signing)

EOF
    exit 1
}

# Function to configure server.xml for the specified mode
configure_server_xml() {
    local mode=$1
    
    print_info "Configuring server.xml for mode: ${mode}"
    
    # Backup server.xml
    cp "${SERVER_XML}" "${SERVER_XML}.backup"
    
    # Read the current server.xml
    local content=$(cat "${SERVER_XML}")
    
    case $mode in
        plain)
            # Enable plain handler, comment out encrypted/signed handler
            content=$(echo "$content" | sed -E '
                /<!-- Plain audit file handler/,/^<\/auditFileHandler>/ {
                    s/^<!-- Plain audit file handler/<!-- Plain audit file handler/
                    s/^<auditFileHandler maxFiles="100"/<auditFileHandler maxFiles="100"/
                    s/^<\/auditFileHandler>/<\/auditFileHandler>/
                }
                /<!-- Encrypted and Signed audit file handler/,/^-->/ {
                    s/^<!-- Encrypted and Signed/<!-- Encrypted and Signed/
                    s/^<auditFileHandler/<!-- <auditFileHandler/
                    s/^<\/auditFileHandler>/<\/auditFileHandler> -->/
                    s/^-->$/-->/
                }
            ')
            ;;
            
        encrypted)
            # Comment out plain handler, enable encrypted handler (without signing)
            print_warning "Encrypted-only mode: Modifying configuration to enable encryption without signing"
            # This requires manual editing - for now, use 'both' mode
            print_error "Encrypted-only mode not yet implemented. Use 'both' mode instead."
            return 1
            ;;
            
        signed)
            # Comment out plain handler, enable signed handler (without encryption)
            print_warning "Signed-only mode: Modifying configuration to enable signing without encryption"
            # This requires manual editing - for now, use 'both' mode
            print_error "Signed-only mode not yet implemented. Use 'both' mode instead."
            return 1
            ;;
            
        both)
            # Comment out plain handler, enable encrypted and signed handler
            content=$(echo "$content" | sed -E '
                /<!-- Plain audit file handler/,/^<\/auditFileHandler>/ {
                    s/^<!-- Plain audit file handler/<!-- Plain audit file handler/
                    s/^<auditFileHandler maxFiles="100"/<!-- <auditFileHandler maxFiles="100"/
                    s/^<\/auditFileHandler>/<\/auditFileHandler> -->/
                }
                /<!-- Encrypted and Signed audit file handler/,/^-->/ {
                    s/^<!-- Encrypted and Signed/<!-- Encrypted and Signed/
                    s/^<!-- <auditFileHandler/<auditFileHandler/
                    s/^<\/auditFileHandler> -->/<\/auditFileHandler>/
                    s/^-->$//
                }
            ')
            ;;
            
        *)
            print_error "Invalid mode: ${mode}"
            return 1
            ;;
    esac
    
    # Write the modified content back
    echo "$content" > "${SERVER_XML}"
    
    print_success "Server configuration updated for ${mode} mode"
    return 0
}

# Function to compile AuditEventTrigger if needed
compile_trigger() {
    if [ ! -f "${AUDIT_TRIGGER}" ] || [ "$FORCE_COMPILE" = true ]; then
        print_info "Compiling AuditEventTrigger.java..."
        javac "${JAVA_SOURCE}"
        if [ $? -eq 0 ]; then
            print_success "Compilation successful"
        else
            print_error "Compilation failed"
            exit 1
        fi
    fi
}

# Function to restart the server
restart_server() {
    print_info "Restarting Open Liberty server..."
    
    cd "${SCRIPT_DIR}/build.image/wlp/bin"
    
    # Stop the server
    print_info "Stopping server..."
    ./server stop defaultServer
    sleep 2
    
    # Start the server
    print_info "Starting server..."
    ./server start defaultServer
    
    # Wait for server to be ready
    print_info "Waiting for server to start..."
    sleep 10
    
    # Check if server is running
    ./server status defaultServer
    if [ $? -eq 0 ]; then
        print_success "Server restarted successfully"
    else
        print_error "Server failed to start"
        exit 1
    fi
    
    cd "${SCRIPT_DIR}"
}

# Function to generate audit events
generate_events() {
    local count=$1
    local duration=$2
    local rate=$3
    local url=$4
    
    print_info "Generating audit events..."
    print_info "  Mode: ${MODE}"
    print_info "  Count: ${count}"
    print_info "  Duration: ${duration} seconds"
    print_info "  Rate: ${rate} events/second"
    print_info "  URL: ${url}"
    
    # Build the command
    local cmd="java AuditEventTrigger --url ${url} --rate ${rate}"
    
    if [ -n "$duration" ] && [ "$duration" != "0" ]; then
        cmd="${cmd} --duration ${duration}"
    else
        cmd="${cmd} --count ${count}"
    fi
    
    print_info "Executing: ${cmd}"
    eval $cmd
    
    if [ $? -eq 0 ]; then
        print_success "Audit event generation completed"
    else
        print_error "Audit event generation failed"
        exit 1
    fi
}

# Parse command line arguments
MODE="plain"
COUNT=1000
DURATION=0
RATE=20
URL="http://localhost:9080"
NO_RESTART=false
FORCE_COMPILE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -c|--count)
            COUNT="$2"
            shift 2
            ;;
        -d|--duration)
            DURATION="$2"
            shift 2
            ;;
        -r|--rate)
            RATE="$2"
            shift 2
            ;;
        -u|--url)
            URL="$2"
            shift 2
            ;;
        --no-restart)
            NO_RESTART=true
            shift
            ;;
        --compile)
            FORCE_COMPILE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate mode
if [[ ! "$MODE" =~ ^(plain|encrypted|signed|both)$ ]]; then
    print_error "Invalid mode: ${MODE}"
    usage
fi

# Main execution
print_info "=== Open Liberty Advanced Audit Event Generator ==="
print_info "Mode: ${MODE}"

# Compile if needed
compile_trigger

# Configure server.xml
configure_server_xml "$MODE"
if [ $? -ne 0 ]; then
    print_error "Failed to configure server"
    exit 1
fi

# Restart server if needed
if [ "$NO_RESTART" = false ]; then
    restart_server
else
    print_warning "Skipping server restart (--no-restart specified)"
    print_warning "Make sure the server is already configured for ${MODE} mode"
fi

# Generate events
generate_events "$COUNT" "$DURATION" "$RATE" "$URL"

print_success "=== Audit event generation complete ==="
print_info "Check audit logs at: ${SCRIPT_DIR}/build.image/wlp/usr/servers/defaultServer/logs/"

# Show audit log location based on mode
if [ "$MODE" = "plain" ]; then
    print_info "Audit log: audit.log"
else
    print_info "Audit log: audit.log (encrypted/signed)"
    print_info "Use AuditLogReader to decrypt/verify: java -jar auditReader.jar"
fi

# Made with Bob
