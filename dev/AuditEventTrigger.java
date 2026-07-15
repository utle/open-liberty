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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import java.util.Random;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

/**
 * Utility to trigger real audit events by making HTTP requests to a running Open Liberty server.
 * This generates actual audit events through the server's audit system.
 * 
 * Usage:
 *   java AuditEventTrigger --url <base-url> [--count <number> | --duration <seconds>]
 *
 * Options:
 *   --url <base-url>      Base URL of the server (e.g., https://localhost:9443)
 *   --count <number>      Generate specified number of events (default: 1000)
 *   --duration <seconds>  Generate events for specified duration in seconds
 *   --rate <events/sec>   Events per second (default: 10)
 *   --username <user>     Username for authentication (default: admin)
 *   --password <pass>     Password for authentication (default: adminpwd)
 *   --help                Display this help message
 *
 * Examples:
 *   java AuditEventTrigger --url https://localhost:9443 --count 5000
 *   java AuditEventTrigger --url https://localhost:9443 --duration 600 --rate 20
 */
public class AuditEventTrigger {
    
    private static final String[] ENDPOINTS = {
        "/auditTest/secure",  // Protected endpoint that requires authentication
        "/auditTest/admin"
    };
    
    private static final String[] METHODS = {
        "GET", "POST", "PUT", "DELETE"
    };
    
    private static final Random random = new Random();
    
    static {
        // Disable SSL certificate validation for testing with self-signed certificates
        try {
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            System.err.println("Warning: Could not disable SSL verification: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        try {
            Config config = parseArgs(args);
            
            if (config.showHelp) {
                printHelp();
                return;
            }
            
            if (config.baseUrl == null) {
                System.err.println("Error: --url parameter is required");
                printHelp();
                System.exit(1);
            }
            
            triggerAuditEvents(config);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static void triggerAuditEvents(Config config) throws IOException, InterruptedException {
        long startTime = System.currentTimeMillis();
        long eventCount = 0;
        long successCount = 0;
        long failureCount = 0;
        
        System.out.println("Starting audit event generation via HTTP requests...");
        System.out.println("Target server: " + config.baseUrl);
        
        if (config.useDuration) {
            System.out.println("Duration: " + config.durationSeconds + " seconds");
            System.out.println("Rate: " + config.eventsPerSecond + " events/second");
            System.out.println("Expected total: ~" + (config.durationSeconds * config.eventsPerSecond) + " events");
        } else {
            System.out.println("Count: " + config.eventCount + " events");
        }
        
        System.out.println("\nGenerating audit events by making HTTP requests...\n");
        
        if (config.useDuration) {
            // Duration-based generation
            long endTime = startTime + (config.durationSeconds * 1000L);
            long delayMs = 1000L / config.eventsPerSecond;
            
            while (System.currentTimeMillis() < endTime) {
                boolean success = makeRequest(config);
                eventCount++;
                if (success) {
                    successCount++;
                } else {
                    failureCount++;
                }
                
                if (eventCount % 10 == 0) {
                    System.out.print("\rGenerated " + eventCount + " events (Success: " + 
                                   successCount + ", Failed: " + failureCount + ")...");
                }
                
                // Rate limiting
                if (delayMs > 0) {
                    Thread.sleep(delayMs);
                }
            }
        } else {
            // Count-based generation
            for (long i = 0; i < config.eventCount; i++) {
                boolean success = makeRequest(config);
                eventCount++;
                if (success) {
                    successCount++;
                } else {
                    failureCount++;
                }
                
                if (eventCount % 10 == 0) {
                    System.out.print("\rGenerated " + eventCount + " events (Success: " + 
                                   successCount + ", Failed: " + failureCount + ")...");
                }
                
                // Small delay to avoid overwhelming the server
                Thread.sleep(10);
            }
        }
        
        long endTime = System.currentTimeMillis();
        double durationSec = (endTime - startTime) / 1000.0;
        double eventsPerSec = eventCount / durationSec;
        
        System.out.println("\n\nGeneration complete!");
        System.out.println("Total requests: " + eventCount);
        System.out.println("Successful: " + successCount);
        System.out.println("Failed: " + failureCount);
        System.out.println("Duration: " + String.format("%.2f", durationSec) + " seconds");
        System.out.println("Average rate: " + String.format("%.2f", eventsPerSec) + " events/second");
        System.out.println("\nCheck your server's audit log for the generated events.");
    }
    
    private static boolean makeRequest(Config config) {
        HttpURLConnection conn = null;
        try {
            // Randomly choose endpoint and method
            String endpoint = ENDPOINTS[random.nextInt(ENDPOINTS.length)];
            String method = METHODS[random.nextInt(METHODS.length)];
            
            // Randomly decide authentication strategy:
            // 1. admin with correct password (adminpass) - 50%
            // 2. admin with wrong password - 50%
            int authChoice = random.nextInt(2);
            String username;
            String password;
            
            if (authChoice == 0) {
                // Correct admin credentials (matches server.xml basicRegistry)
                username = "admin";
                password = "adminpass";
            } else {
                // Wrong admin password - this should trigger SECURITY_AUTHN_FAILURE
                username = "admin";
                password = "wrongpassword";
            }
            
            URL url = new URL(config.baseUrl + endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            
            // Add authentication header if username is set
            if (username != null) {
                String auth = username + ":" + password;
                String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
                conn.setRequestProperty("Authorization", "Basic " + encodedAuth);
            }
            
            // Make the request and consume the response
            int responseCode = conn.getResponseCode();
            
            // IMPORTANT: Must read the response stream to ensure the request completes
            // and audit events are properly flushed. This is critical for failed auth events.
            try {
                if (responseCode >= 200 && responseCode < 300) {
                    // Success response - read input stream
                    java.io.InputStream is = conn.getInputStream();
                    while (is.read() != -1) {
                        // Consume the stream
                    }
                    is.close();
                } else {
                    // Error response - read error stream
                    java.io.InputStream es = conn.getErrorStream();
                    if (es != null) {
                        while (es.read() != -1) {
                            // Consume the stream
                        }
                        es.close();
                    }
                }
            } catch (Exception e) {
                // Ignore stream reading errors
            }
            
            // Any response (including 401, 403, 404) generates an audit event
            return true;
            
        } catch (Exception e) {
            // Connection failures still count as attempts
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    
    private static Config parseArgs(String[] args) {
        Config config = new Config();
        
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--help":
                case "-h":
                    config.showHelp = true;
                    return config;
                    
                case "--url":
                case "-u":
                    if (i + 1 < args.length) {
                        config.baseUrl = args[++i];
                        // Remove trailing slash if present
                        if (config.baseUrl.endsWith("/")) {
                            config.baseUrl = config.baseUrl.substring(0, config.baseUrl.length() - 1);
                        }
                    } else {
                        throw new IllegalArgumentException("--url requires a URL");
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
                    
                case "--username":
                    if (i + 1 < args.length) {
                        config.username = args[++i];
                    } else {
                        throw new IllegalArgumentException("--username requires a value");
                    }
                    break;
                    
                case "--password":
                    if (i + 1 < args.length) {
                        config.password = args[++i];
                    } else {
                        throw new IllegalArgumentException("--password requires a value");
                    }
                    break;
                    
                default:
                    throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
        }
        
        return config;
    }
    
    private static void printHelp() {
        System.out.println("Audit Event Trigger - Generate real audit events via HTTP requests");
        System.out.println();
        System.out.println("This utility makes HTTP requests to a running Open Liberty server to trigger");
        System.out.println("actual audit events through the server's audit system.");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java AuditEventTrigger --url <base-url> [--count <number> | --duration <seconds>]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --url, -u <base-url>      Base URL of the server (required)");
        System.out.println("                            Example: https://localhost:9443");
        System.out.println("  --count, -c <number>      Generate specified number of events (default: 1000)");
        System.out.println("  --duration, -d <seconds>  Generate events for specified duration in seconds");
        System.out.println("  --rate, -r <events/sec>   Events per second (default: 10)");
        System.out.println("  --username <user>         Username for authentication (default: admin)");
        System.out.println("  --password <pass>         Password for authentication (default: adminpwd)");
        System.out.println("  --help, -h                Display this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Generate 5000 events by making HTTPS requests");
        System.out.println("  java AuditEventTrigger --url https://localhost:9443 --count 5000");
        System.out.println();
        System.out.println("  # Generate events for 10 minutes (600 seconds) at 20 events/second");
        System.out.println("  java AuditEventTrigger --url https://localhost:9443 --duration 600 --rate 20");
        System.out.println();
        System.out.println("  # Generate events with custom credentials");
        System.out.println("  java AuditEventTrigger --url https://localhost:9443 --count 1000 \\");
        System.out.println("       --username testuser --password testpass");
        System.out.println();
        System.out.println("Note: The server must be running and have audit logging enabled.");
        System.out.println("      The utility makes HTTPS requests to auditTest servlet endpoints.");
        System.out.println("      It generates 50% successful (admin/adminpwd) and 50% failed");
        System.out.println("      (admin/wrongpassword) authentication attempts.");
    }
    
    private static class Config {
        String baseUrl = null;
        long eventCount = 1000;
        long durationSeconds = 60;
        long eventsPerSecond = 10;
        String username = "admin";
        String password = "adminpass";
        boolean useDuration = false;
        boolean showHelp = false;
    }
}

// Made with Bob
