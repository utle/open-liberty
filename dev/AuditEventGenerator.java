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

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

/**
 * Standalone utility to generate thousands of audit events for testing purposes.
 * This utility writes audit events directly to a file in the Open Liberty audit log JSON format.
 * 
 * Usage:
 *   java AuditEventGenerator --output <file> [--count <number> | --duration <seconds>]
 * 
 * Options:
 *   --output <file>       Output file path (required)
 *   --count <number>      Generate specified number of events (default: 1000)
 *   --duration <seconds>  Generate events for specified duration in seconds
 *   --rate <events/sec>   Events per second when using duration mode (default: 10)
 *   --help                Display this help message
 * 
 * Examples:
 *   java AuditEventGenerator --output audit.log --count 5000
 *   java AuditEventGenerator --output audit.log --duration 600 --rate 20
 */
public class AuditEventGenerator {
    
    private static final String[] EVENT_TYPES = {
        "SECURITY_AUTHN",
        "SECURITY_AUTHZ",
        "SECURITY_AUDIT_MGMT",
        "JMX_MBEAN",
        "JMX_MBEAN_ATTRIBUTES"
    };
    
    private static final String[] OUTCOMES = {
        "success",
        "failure",
        "challenge",
        "redirect"
    };
    
    private static final String[] USERNAMES = {
        "user1", "user2", "user3", "admin", "testuser",
        "developer", "operator", "guest", "service_account", "api_user"
    };
    
    private static final String[] METHODS = {
        "GET", "POST", "PUT", "DELETE", "PATCH"
    };
    
    private static final String[] RESOURCES = {
        "/api/users", "/api/orders", "/api/products", "/api/auth",
        "/admin/config", "/admin/users", "/health", "/metrics",
        "/app/dashboard", "/app/reports"
    };
    
    private static final Random random = new Random();
    private static String hostname;
    private static String serverPath;
    
    static {
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            hostname = "localhost";
        }
        serverPath = "websphere: " + hostname + ":/opt/ibm/wlp/usr/:defaultServer";
    }
    
    public static void main(String[] args) {
        try {
            Config config = parseArgs(args);
            
            if (config.showHelp) {
                printHelp();
                return;
            }
            
            if (config.outputFile == null) {
                System.err.println("Error: --output parameter is required");
                printHelp();
                System.exit(1);
            }
            
            generateAuditEvents(config);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static void generateAuditEvents(Config config) throws IOException {
        long startTime = System.currentTimeMillis();
        long eventCount = 0;
        long sequenceNumber = 0;
        
        System.out.println("Starting audit event generation...");
        System.out.println("Output file: " + config.outputFile);
        
        if (config.useDuration) {
            System.out.println("Duration: " + config.durationSeconds + " seconds");
            System.out.println("Rate: " + config.eventsPerSecond + " events/second");
            System.out.println("Expected total: ~" + (config.durationSeconds * config.eventsPerSecond) + " events");
        } else {
            System.out.println("Count: " + config.eventCount + " events");
        }
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(config.outputFile))) {
            
            if (config.useDuration) {
                // Duration-based generation
                long endTime = startTime + (config.durationSeconds * 1000L);
                long delayMs = 1000L / config.eventsPerSecond;
                
                while (System.currentTimeMillis() < endTime) {
                    String event = generateAuditEvent(sequenceNumber++);
                    writer.write(event);
                    writer.newLine();
                    eventCount++;
                    
                    if (eventCount % 100 == 0) {
                        System.out.print("\rGenerated " + eventCount + " events...");
                    }
                    
                    // Rate limiting
                    if (delayMs > 0) {
                        try {
                            Thread.sleep(delayMs);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            } else {
                // Count-based generation
                for (long i = 0; i < config.eventCount; i++) {
                    String event = generateAuditEvent(sequenceNumber++);
                    writer.write(event);
                    writer.newLine();
                    eventCount++;
                    
                    if (eventCount % 100 == 0) {
                        System.out.print("\rGenerated " + eventCount + " events...");
                    }
                }
            }
        }
        
        long endTime = System.currentTimeMillis();
        double durationSec = (endTime - startTime) / 1000.0;
        double eventsPerSec = eventCount / durationSec;
        
        System.out.println("\n\nGeneration complete!");
        System.out.println("Total events: " + eventCount);
        System.out.println("Duration: " + String.format("%.2f", durationSec) + " seconds");
        System.out.println("Average rate: " + String.format("%.2f", eventsPerSec) + " events/second");
        System.out.println("Output file: " + config.outputFile);
    }
    
    private static String generateAuditEvent(long sequenceNumber) {
        String eventType = EVENT_TYPES[random.nextInt(EVENT_TYPES.length)];
        String outcome = OUTCOMES[random.nextInt(OUTCOMES.length)];
        String timestamp = ZonedDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("   \"eventName\": \"").append(eventType).append("\",\n");
        json.append("   \"eventSequenceNumber\": \"").append(sequenceNumber).append("\",\n");
        json.append("   \"eventTime\": \"").append(timestamp).append("\",\n");
        
        // Observer section
        json.append("   \"observer\": {\n");
        json.append("      \"id\": \"").append(serverPath).append("\",\n");
        json.append("      \"name\": \"SecurityService\",\n");
        json.append("      \"typeURI\": \"service/server\"\n");
        json.append("   },\n");
        
        json.append("   \"outcome\": \"").append(outcome).append("\",\n");
        
        // Target section - varies by event type
        json.append("   \"target\": {\n");
        json.append("      \"id\": \"").append(serverPath).append("\",\n");
        
        if (eventType.equals("SECURITY_AUTHN") || eventType.equals("SECURITY_AUTHZ")) {
            String username = USERNAMES[random.nextInt(USERNAMES.length)];
            String method = METHODS[random.nextInt(METHODS.length)];
            String resource = RESOURCES[random.nextInt(RESOURCES.length)];
            
            json.append("      \"name\": \"").append(resource).append("\",\n");
            json.append("      \"method\": \"").append(method).append("\",\n");
            json.append("      \"credential.token\": \"").append(username).append("\",\n");
            json.append("      \"credential.type\": \"BASIC\",\n");
            json.append("      \"host.address\": \"127.0.0.1:9443\",\n");
            json.append("      \"realm\": \"defaultRealm\",\n");
            json.append("      \"typeURI\": \"service/application/web\"\n");
        } else if (eventType.equals("JMX_MBEAN") || eventType.equals("JMX_MBEAN_ATTRIBUTES")) {
            json.append("      \"jmx.mbean.name\": \"WebSphere:name=TestMBean").append(random.nextInt(100)).append("\",\n");
            json.append("      \"jmx.mbean.action\": \"invoke\",\n");
            json.append("      \"typeURI\": \"server/mbean\"\n");
        } else {
            json.append("      \"typeURI\": \"service/audit/test\"\n");
        }
        
        json.append("   }\n");
        json.append("}");
        
        return json.toString();
    }
    
    private static Config parseArgs(String[] args) {
        Config config = new Config();
        
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help":
                case "-h":
                    config.showHelp = true;
                    return config;
                    
                case "--output":
                case "-o":
                    if (i + 1 < args.length) {
                        config.outputFile = args[++i];
                    } else {
                        throw new IllegalArgumentException("--output requires a file path");
                    }
                    break;
                    
                case "--count":
                case "-c":
                    if (i + 1 < args.length) {
                        config.eventCount = Long.parseLong(args[++i]);
                        config.useDuration = false;
                    } else {
                        throw new IllegalArgumentException("--count requires a number");
                    }
                    break;
                    
                case "--duration":
                case "-d":
                    if (i + 1 < args.length) {
                        config.durationSeconds = Long.parseLong(args[++i]);
                        config.useDuration = true;
                    } else {
                        throw new IllegalArgumentException("--duration requires a number of seconds");
                    }
                    break;
                    
                case "--rate":
                case "-r":
                    if (i + 1 < args.length) {
                        config.eventsPerSecond = Long.parseLong(args[++i]);
                    } else {
                        throw new IllegalArgumentException("--rate requires a number");
                    }
                    break;
                    
                default:
                    throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        
        return config;
    }
    
    private static void printHelp() {
        System.out.println("Audit Event Generator - Generate thousands of audit events for testing");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java AuditEventGenerator --output <file> [--count <number> | --duration <seconds>]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --output, -o <file>       Output file path (required)");
        System.out.println("  --count, -c <number>      Generate specified number of events (default: 1000)");
        System.out.println("  --duration, -d <seconds>  Generate events for specified duration in seconds");
        System.out.println("  --rate, -r <events/sec>   Events per second when using duration mode (default: 10)");
        System.out.println("  --help, -h                Display this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Generate 5000 events");
        System.out.println("  java AuditEventGenerator --output audit.log --count 5000");
        System.out.println();
        System.out.println("  # Generate events for 10 minutes (600 seconds) at 20 events/second");
        System.out.println("  java AuditEventGenerator --output audit.log --duration 600 --rate 20");
        System.out.println();
        System.out.println("  # Generate events for 5 minutes at default rate (10 events/second)");
        System.out.println("  java AuditEventGenerator --output audit.log --duration 300");
    }
    
    private static class Config {
        String outputFile = null;
        long eventCount = 1000;
        long durationSeconds = 60;
        long eventsPerSecond = 10;
        boolean useDuration = false;
        boolean showHelp = false;
    }
}

// Made with Bob
