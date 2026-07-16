#!/bin/bash

# Test script to regenerate audit comparison with fixed tool
# This uses existing audit logs to demonstrate the fix

cd /Users/niyathar/libertyGit/open-liberty/dev

echo "=== Testing Fixed Audit Comparison Tool ==="
echo ""

# Check if we have the audit log
if [ ! -f "build.image/wlp/usr/servers/defaultServer/logs/audit-output.log" ]; then
    echo "Error: No audit log found at build.image/wlp/usr/servers/defaultServer/logs/audit-output.log"
    echo "Please run the server and generate some audit events first."
    exit 1
fi

# Create output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="audit-comparison-results/test_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo "Using existing audit log for demonstration..."
cp build.image/wlp/usr/servers/defaultServer/logs/audit-output.log "$OUTPUT_DIR/audit-test.log"

# For demonstration, we'll use the same log twice (in real scenario, you'd have PQC enabled/disabled logs)
echo ""
echo "Generating HTML report..."
java AuditComparisonTool \
    "$OUTPUT_DIR/audit-test.log" \
    "$OUTPUT_DIR/audit-test.log" \
    "$OUTPUT_DIR/comparison-report.html"

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Report generated successfully!"
    echo "  Location: $OUTPUT_DIR/comparison-report.html"
    echo ""
    echo "Open the report with:"
    echo "  open $OUTPUT_DIR/comparison-report.html"
else
    echo ""
    echo "✗ Report generation failed"
    exit 1
fi

# Made with Bob
