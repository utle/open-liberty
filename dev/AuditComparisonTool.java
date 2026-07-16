/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 * 
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/

import java.io.*;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.*;

/**
 * Tool to compare audit log performance between PQC enabled and disabled modes.
 * Generates an HTML report showing timing differences and success/failure rates.
 */
public class AuditComparisonTool {
    
    private static class AuditEvent {
        String timestamp;
        String eventName;
        String outcome;
        String targetName;
        String targetMethod;
        String credentialType;
        String credentialValue;
        String realm;
        int statusCode;
        long timeMs;
        
        @Override
        public String toString() {
            return String.format("%s | %s | %s | %s %s | %s | %d",
                timestamp, eventName, outcome, targetMethod, targetName, credentialValue, statusCode);
        }
    }
    
    private static class ComparisonResult {
        List<AuditEvent> pqcDisabledEvents = new ArrayList<>();
        List<AuditEvent> pqcEnabledEvents = new ArrayList<>();
        long pqcDisabledTotalTime;
        long pqcEnabledTotalTime;
        int pqcDisabledSuccessCount;
        int pqcDisabledDeniedCount;
        int pqcEnabledSuccessCount;
        int pqcEnabledDeniedCount;
    }
    
    public static void main(String[] args) {
        if (args.length < 3) {
            System.err.println("Usage: java AuditComparisonTool <pqc-disabled-log> <pqc-enabled-log> <output-html>");
            System.err.println("Example: java AuditComparisonTool audit-nopqc.log audit-pqc.log comparison.html");
            System.exit(1);
        }
        
        String pqcDisabledLog = args[0];
        String pqcEnabledLog = args[1];
        String outputHtml = args[2];
        
        try {
            System.out.println("Parsing PQC disabled log: " + pqcDisabledLog);
            List<AuditEvent> pqcDisabledEvents = parseAuditLog(pqcDisabledLog);
            
            System.out.println("Parsing PQC enabled log: " + pqcEnabledLog);
            List<AuditEvent> pqcEnabledEvents = parseAuditLog(pqcEnabledLog);
            
            System.out.println("Generating comparison report...");
            ComparisonResult result = new ComparisonResult();
            result.pqcDisabledEvents = pqcDisabledEvents;
            result.pqcEnabledEvents = pqcEnabledEvents;
            
            // Calculate statistics
            calculateStatistics(result);
            
            // Generate HTML report
            generateHtmlReport(result, outputHtml);
            
            System.out.println("\nComparison complete!");
            System.out.println("Report saved to: " + outputHtml);
            System.out.println("\nSummary:");
            System.out.println("PQC Disabled: " + pqcDisabledEvents.size() + " events, " +
                             result.pqcDisabledSuccessCount + " success, " +
                             result.pqcDisabledDeniedCount + " denied");
            System.out.println("PQC Enabled:  " + pqcEnabledEvents.size() + " events, " +
                             result.pqcEnabledSuccessCount + " success, " +
                             result.pqcEnabledDeniedCount + " denied");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static List<AuditEvent> parseAuditLog(String logPath) throws IOException {
        List<AuditEvent> events = new ArrayList<>();
        String content = new String(Files.readAllBytes(Paths.get(logPath)));
        
        // Parse JSON audit events - need to handle nested braces
        int pos = 0;
        long firstTimestamp = -1;
        
        while (pos < content.length()) {
            int start = content.indexOf('{', pos);
            if (start == -1) break;
            
            // Find matching closing brace
            int braceCount = 1;
            int end = start + 1;
            while (end < content.length() && braceCount > 0) {
                char c = content.charAt(end);
                if (c == '{') braceCount++;
                else if (c == '}') braceCount--;
                end++;
            }
            
            if (braceCount == 0) {
                String eventJson = content.substring(start, end);
                AuditEvent event = parseEvent(eventJson);
                if (event != null && "SECURITY_AUTHN".equals(event.eventName)) {
                    // Calculate relative time
                    if (firstTimestamp == -1) {
                        firstTimestamp = parseTimestamp(event.timestamp);
                        event.timeMs = 0;
                    } else {
                        event.timeMs = parseTimestamp(event.timestamp) - firstTimestamp;
                    }
                    events.add(event);
                }
            }
            
            pos = end;
        }
        
        return events;
    }
    
    private static AuditEvent parseEvent(String json) {
        AuditEvent event = new AuditEvent();
        
        event.timestamp = extractValue(json, "eventTime");
        event.eventName = extractValue(json, "eventName");
        event.outcome = extractValue(json, "outcome");
        event.targetName = extractValue(json, "target.name");
        event.targetMethod = extractValue(json, "target.method");
        event.credentialType = extractValue(json, "target.credential.type");
        event.credentialValue = extractValue(json, "target.credential.token");
        event.realm = extractValue(json, "target.realm");
        
        String statusCodeStr = extractValue(json, "reason.reasonCode");
        try {
            event.statusCode = Integer.parseInt(statusCodeStr);
        } catch (NumberFormatException e) {
            event.statusCode = 0;
        }
        
        return event.eventName != null ? event : null;
    }
    
    private static String extractValue(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        return matcher.find() ? matcher.group(1) : "";
    }
    
    private static long parseTimestamp(String timestamp) {
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            return sdf.parse(timestamp.replaceAll("Z$", "+0000")).getTime();
        } catch (Exception e) {
            return 0;
        }
    }
    
    private static void calculateStatistics(ComparisonResult result) {
        for (AuditEvent event : result.pqcDisabledEvents) {
            if ("success".equals(event.outcome)) {
                result.pqcDisabledSuccessCount++;
            } else if ("denied".equals(event.outcome)) {
                result.pqcDisabledDeniedCount++;
            }
        }
        
        for (AuditEvent event : result.pqcEnabledEvents) {
            if ("success".equals(event.outcome)) {
                result.pqcEnabledSuccessCount++;
            } else if ("denied".equals(event.outcome)) {
                result.pqcEnabledDeniedCount++;
            }
        }
        
        if (!result.pqcDisabledEvents.isEmpty()) {
            result.pqcDisabledTotalTime = result.pqcDisabledEvents.get(
                result.pqcDisabledEvents.size() - 1).timeMs;
        }
        
        if (!result.pqcEnabledEvents.isEmpty()) {
            result.pqcEnabledTotalTime = result.pqcEnabledEvents.get(
                result.pqcEnabledEvents.size() - 1).timeMs;
        }
    }
    
    private static void generateHtmlReport(ComparisonResult result, String outputPath) throws IOException {
        StringBuilder html = new StringBuilder();
        
        html.append("<!DOCTYPE html>\n");
        html.append("<html>\n<head>\n");
        html.append("<meta charset='UTF-8'>\n");
        html.append("<title>Audit Log PQC Performance Comparison</title>\n");
        html.append("<style>\n");
        html.append("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f8f9fa; color: #212529; }\n");
        html.append("h1 { color: #1a1a1a; border-bottom: 4px solid #0066cc; padding-bottom: 12px; font-size: 28px; }\n");
        html.append("h2 { color: #2c3e50; margin-top: 35px; font-size: 22px; border-left: 4px solid #0066cc; padding-left: 12px; }\n");
        html.append(".summary { background: white; padding: 25px; border-radius: 10px; margin: 25px 0; box-shadow: 0 3px 6px rgba(0,0,0,0.12); border: 1px solid #e0e0e0; }\n");
        html.append(".stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 25px; margin: 25px 0; }\n");
        html.append(".stat-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 3px 6px rgba(0,0,0,0.12); border: 1px solid #e0e0e0; transition: transform 0.2s; }\n");
        html.append(".stat-card:hover { transform: translateY(-2px); box-shadow: 0 5px 12px rgba(0,0,0,0.15); }\n");
        html.append(".stat-card h3 { margin-top: 0; color: #495057; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; }\n");
        html.append(".stat-value { font-size: 36px; font-weight: bold; color: #0066cc; margin: 10px 0; }\n");
        html.append(".stat-label { color: #6c757d; font-size: 13px; }\n");
        html.append(".comparison { background: white; padding: 25px; border-radius: 10px; margin: 25px 0; box-shadow: 0 3px 6px rgba(0,0,0,0.12); border: 1px solid #e0e0e0; overflow-x: auto; }\n");
        html.append("table { width: 100%; border-collapse: collapse; background: white; font-size: 14px; }\n");
        html.append("th { background: linear-gradient(135deg, #0066cc 0%, #004c99 100%); color: white; padding: 14px 12px; text-align: left; position: sticky; top: 0; font-weight: 600; border-bottom: 2px solid #003d7a; }\n");
        html.append("td { padding: 12px; border-bottom: 1px solid #e9ecef; }\n");
        html.append("tr:nth-child(even) { background: #f8f9fa; }\n");
        html.append("tr:hover { background: #e3f2fd; }\n");
        html.append(".success { color: #28a745; font-weight: 600; background: #d4edda; padding: 4px 8px; border-radius: 4px; }\n");
        html.append(".failure { color: #dc3545; font-weight: 600; background: #f8d7da; padding: 4px 8px; border-radius: 4px; }\n");
        html.append(".denied { color: #fd7e14; font-weight: 600; background: #fff3cd; padding: 4px 8px; border-radius: 4px; }\n");
        html.append(".challenge { color: #007bff; font-weight: 600; background: #cfe2ff; padding: 4px 8px; border-radius: 4px; }\n");
        html.append(".faster { background: #d1f2eb; }\n");
        html.append(".slower { background: #f8d7da; }\n");
        html.append(".time-diff { font-weight: 700; font-family: 'Courier New', monospace; }\n");
        html.append(".positive { color: #28a745; }\n");
        html.append(".negative { color: #dc3545; }\n");
        html.append("@media (max-width: 768px) { body { margin: 10px; } .stats { grid-template-columns: 1fr; } }\n");
        html.append("</style>\n");
        html.append("</head>\n<body>\n");
        
        html.append("<h1>🔐 Audit Log PQC Performance Comparison</h1>\n");
        html.append("<p>Comparison of 100 authentication audit events with PQC disabled vs enabled</p>\n");
        
        // Summary statistics
        html.append("<div class='stats'>\n");
        
        // PQC Disabled stats
        html.append("<div class='stat-card'>\n");
        html.append("<h3>PQC Disabled</h3>\n");
        html.append("<div class='stat-value'>").append(result.pqcDisabledEvents.size()).append("</div>\n");
        html.append("<div class='stat-label'>Total Events</div>\n");
        html.append("<div style='margin-top: 15px;'>\n");
        html.append("<span class='success'>✓ ").append(result.pqcDisabledSuccessCount).append(" Success</span><br>\n");
        html.append("<span class='denied'>✗ ").append(result.pqcDisabledDeniedCount).append(" Denied</span>\n");
        html.append("</div>\n");
        html.append("<div style='margin-top: 15px; font-size: 18px; color: #666;'>\n");
        html.append("Total Time: <strong>").append(result.pqcDisabledTotalTime).append(" ms</strong>\n");
        html.append("</div>\n");
        html.append("</div>\n");
        
        // PQC Enabled stats
        html.append("<div class='stat-card'>\n");
        html.append("<h3>PQC Enabled</h3>\n");
        html.append("<div class='stat-value'>").append(result.pqcEnabledEvents.size()).append("</div>\n");
        html.append("<div class='stat-label'>Total Events</div>\n");
        html.append("<div style='margin-top: 15px;'>\n");
        html.append("<span class='success'>✓ ").append(result.pqcEnabledSuccessCount).append(" Success</span><br>\n");
        html.append("<span class='denied'>✗ ").append(result.pqcEnabledDeniedCount).append(" Denied</span>\n");
        html.append("</div>\n");
        html.append("<div style='margin-top: 15px; font-size: 18px; color: #666;'>\n");
        html.append("Total Time: <strong>").append(result.pqcEnabledTotalTime).append(" ms</strong>\n");
        html.append("</div>\n");
        html.append("</div>\n");
        
        // Performance difference
        html.append("<div class='stat-card'>\n");
        html.append("<h3>Performance Impact</h3>\n");
        long timeDiff = result.pqcEnabledTotalTime - result.pqcDisabledTotalTime;
        double percentDiff = result.pqcDisabledTotalTime > 0 ? 
            (timeDiff * 100.0 / result.pqcDisabledTotalTime) : 0;
        String diffClass = timeDiff > 0 ? "negative" : "positive";
        html.append("<div class='stat-value ").append(diffClass).append("'>")
            .append(timeDiff > 0 ? "+" : "").append(timeDiff).append(" ms</div>\n");
        html.append("<div class='stat-label'>Time Difference</div>\n");
        html.append("<div style='margin-top: 15px; font-size: 24px;' class='").append(diffClass).append("'>\n");
        html.append(String.format("%+.1f%%", percentDiff)).append("\n");
        html.append("</div>\n");
        html.append("</div>\n");
        
        html.append("</div>\n");
        
        // Side-by-side comparison table
        html.append("<h2>Event-by-Event Comparison</h2>\n");
        html.append("<div class='comparison'>\n");
        html.append("<table>\n");
        html.append("<tr>\n");
        html.append("<th>#</th>\n");
        html.append("<th>Time (ms)</th>\n");
        html.append("<th>User</th>\n");
        html.append("<th>Method</th>\n");
        html.append("<th>Endpoint</th>\n");
        html.append("<th>Outcome</th>\n");
        html.append("<th>Time (ms)</th>\n");
        html.append("<th>User</th>\n");
        html.append("<th>Method</th>\n");
        html.append("<th>Endpoint</th>\n");
        html.append("<th>Outcome</th>\n");
        html.append("<th>Δ Time</th>\n");
        html.append("</tr>\n");
        
        int maxEvents = Math.max(result.pqcDisabledEvents.size(), result.pqcEnabledEvents.size());
        for (int i = 0; i < maxEvents; i++) {
            AuditEvent disabledEvent = i < result.pqcDisabledEvents.size() ?
                result.pqcDisabledEvents.get(i) : null;
            AuditEvent enabledEvent = i < result.pqcEnabledEvents.size() ?
                result.pqcEnabledEvents.get(i) : null;
            
            html.append("<tr>\n");
            html.append("<td>").append(i + 1).append("</td>\n");
            
            // PQC Disabled
            if (disabledEvent != null) {
                html.append("<td>").append(disabledEvent.timeMs).append("</td>\n");
                html.append("<td>").append(disabledEvent.credentialValue != null ? disabledEvent.credentialValue : "-").append("</td>\n");
                html.append("<td>").append(disabledEvent.targetMethod != null ? disabledEvent.targetMethod : "-").append("</td>\n");
                html.append("<td>").append(disabledEvent.targetName != null ? disabledEvent.targetName : "-").append("</td>\n");
                html.append("<td class='").append(getOutcomeClass(disabledEvent.outcome)).append("'>")
                    .append(disabledEvent.outcome).append("</td>\n");
            } else {
                html.append("<td colspan='5'>-</td>\n");
            }
            
            // PQC Enabled
            if (enabledEvent != null) {
                html.append("<td>").append(enabledEvent.timeMs).append("</td>\n");
                html.append("<td>").append(enabledEvent.credentialValue != null ? enabledEvent.credentialValue : "-").append("</td>\n");
                html.append("<td>").append(enabledEvent.targetMethod != null ? enabledEvent.targetMethod : "-").append("</td>\n");
                html.append("<td>").append(enabledEvent.targetName != null ? enabledEvent.targetName : "-").append("</td>\n");
                html.append("<td class='").append(getOutcomeClass(enabledEvent.outcome)).append("'>")
                    .append(enabledEvent.outcome).append("</td>\n");
            } else {
                html.append("<td colspan='5'>-</td>\n");
            }
            
            // Time difference
            if (disabledEvent != null && enabledEvent != null) {
                long diff = enabledEvent.timeMs - disabledEvent.timeMs;
                String timeDiffClass = diff > 0 ? "negative" : "positive";
                html.append("<td class='time-diff ").append(timeDiffClass).append("'>")
                    .append(diff > 0 ? "+" : "").append(diff).append("</td>\n");
            } else {
                html.append("<td>-</td>\n");
            }
            
            html.append("</tr>\n");
        }
        
        html.append("</table>\n");
        html.append("</div>\n");
        
        html.append("</body>\n</html>");
        
        Files.write(Paths.get(outputPath), html.toString().getBytes());
    }
    
    private static String getOutcomeClass(String outcome) {
        if (outcome == null) return "";
        switch (outcome.toLowerCase()) {
            case "success": return "success";
            case "failure": return "failure";
            case "denied": return "denied";
            case "challenge": return "challenge";
            default: return "";
        }
    }
}

// Made with Bob
