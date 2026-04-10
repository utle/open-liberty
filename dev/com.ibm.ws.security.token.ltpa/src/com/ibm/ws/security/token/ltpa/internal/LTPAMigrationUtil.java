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
package com.ibm.ws.security.token.ltpa.internal;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyUtil;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPQCKeyUtil;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.LTPAPublicKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPrivateKey;
import com.ibm.ws.crypto.ltpakeyutil.MLDSAPublicKey;
import com.ibm.wsspi.security.ltpa.Token;

/**
 * Utility class for migrating LTPA keys and tokens from RSA to PQC.
 * Provides tools for key migration, token conversion, and configuration updates.
 */
public class LTPAMigrationUtil {
    
    private static final TraceComponent tc = Tr.register(LTPAMigrationUtil.class, TraceConstants.TRACE_GROUP, TraceConstants.MESSAGE_BUNDLE);
    
    /**
     * Migration strategy enumeration
     */
    public enum MigrationStrategy {
        /** Add PQC keys while keeping RSA keys (recommended) */
        ADD_PQC_KEYS,
        /** Replace RSA keys with PQC keys (not recommended) */
        REPLACE_WITH_PQC,
        /** Generate new hybrid key set */
        GENERATE_HYBRID
    }
    
    /**
     * Migrate an existing LTPA key file to include PQC keys
     * 
     * @param keyFilePath Path to existing ltpa.keys file
     * @param outputPath Path for output file (can be same as input)
     * @param securityLevel PQC security level (2, 3, or 5)
     * @param strategy Migration strategy
     * @param password Key file password
     * @return true if migration successful
     */
    public static boolean migrateKeyFile(String keyFilePath, String outputPath, 
                                        int securityLevel, MigrationStrategy strategy,
                                        @Sensitive String password) {
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Migrating key file: " + keyFilePath + " with strategy: " + strategy);
        }
        
        try {
            // Load existing keys
            Properties existingKeys = loadKeyFile(keyFilePath, password);
            
            if (existingKeys == null) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isErrorEnabled()) {
                    Tr.error(tc, "Failed to load existing key file: " + keyFilePath);
                }
                return false;
            }
            
            // Check if PQC keys already exist
            if (LTPAPQCKeyUtil.hasPQCKeys(existingKeys)) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                    Tr.warning(tc, "Key file already contains PQC keys: " + keyFilePath);
                }
                return true; // Already migrated
            }
            
            Properties migratedKeys;
            
            switch (strategy) {
                case ADD_PQC_KEYS:
                    migratedKeys = addPQCKeys(existingKeys, securityLevel);
                    break;
                    
                case REPLACE_WITH_PQC:
                    migratedKeys = replacWithPQCKeys(existingKeys, securityLevel);
                    break;
                    
                case GENERATE_HYBRID:
                    migratedKeys = LTPAPQCKeyUtil.generateHybridKeys(securityLevel);
                    break;
                    
                default:
                    throw new IllegalArgumentException("Unknown migration strategy: " + strategy);
            }
            
            // Save migrated keys
            boolean saved = saveKeyFile(outputPath, migratedKeys, password);
            
            if (saved && TraceComponent.isAnyTracingEnabled() && tc.isInfoEnabled()) {
                Tr.info(tc, "Key file migrated successfully: " + outputPath);
            }
            
            return saved;
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isErrorEnabled()) {
                Tr.error(tc, "Error migrating key file: " + e.getMessage(), e);
            }
            return false;
        }
    }
    
    /**
     * Add PQC keys to existing RSA keys
     */
    private static Properties addPQCKeys(Properties existingKeys, int securityLevel) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Adding PQC keys to existing RSA keys");
        }
        
        // Generate PQC keys
        Properties pqcKeys = LTPAPQCKeyUtil.generatePQCKeys(securityLevel);
        
        // Merge with existing keys
        Properties merged = new Properties();
        merged.putAll(existingKeys);
        merged.putAll(pqcKeys);
        
        return merged;
    }
    
    /**
     * Replace RSA keys with PQC keys (not recommended)
     */
    private static Properties replaceWithPQCKeys(Properties existingKeys, int securityLevel) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
            Tr.warning(tc, "Replacing RSA keys with PQC keys - this will break compatibility with existing tokens!");
        }
        
        // Generate PQC keys
        Properties pqcKeys = LTPAPQCKeyUtil.generatePQCKeys(securityLevel);
        
        // Keep only metadata from existing keys
        Properties replaced = new Properties();
        replaced.putAll(pqcKeys);
        
        // Preserve any custom properties
        for (String key : existingKeys.stringPropertyNames()) {
            if (!key.startsWith("com.ibm.websphere.ltpa.")) {
                replaced.setProperty(key, existingKeys.getProperty(key));
            }
        }
        
        return replaced;
    }
    
    /**
     * Load a key file
     */
    private static Properties loadKeyFile(String filePath, @Sensitive String password) {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            Properties props = new Properties();
            props.load(fis);
            
            // TODO: Decrypt if encrypted with password
            // For now, assume unencrypted or handle encryption separately
            
            return props;
        } catch (IOException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isErrorEnabled()) {
                Tr.error(tc, "Error loading key file: " + e.getMessage());
            }
            return null;
        }
    }
    
    /**
     * Save a key file
     */
    private static boolean saveKeyFile(String filePath, Properties keys, @Sensitive String password) {
        try {
            // Create backup of existing file
            File file = new File(filePath);
            if (file.exists()) {
                File backup = new File(filePath + ".backup." + System.currentTimeMillis());
                if (!file.renameTo(backup)) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                        Tr.warning(tc, "Failed to create backup of existing key file");
                    }
                }
            }
            
            // Save new keys
            try (FileOutputStream fos = new FileOutputStream(filePath)) {
                keys.store(fos, "LTPA Keys with PQC Support - Generated: " + new java.util.Date());
            }
            
            // TODO: Encrypt with password if provided
            
            return true;
        } catch (IOException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isErrorEnabled()) {
                Tr.error(tc, "Error saving key file: " + e.getMessage());
            }
            return false;
        }
    }
    
    /**
     * Convert a batch of tokens from one algorithm to another
     * 
     * @param tokens Array of tokens to convert
     * @param targetAlgorithm Target signature algorithm
     * @param sharedKey Shared encryption key
     * @param rsaPrivateKey RSA private key
     * @param rsaPublicKey RSA public key
     * @param pqcPrivateKey PQC private key
     * @param pqcPublicKey PQC public key
     * @return Array of converted tokens
     */
    public static Token[] convertTokens(Token[] tokens, SignatureAlgorithm targetAlgorithm,
                                       @Sensitive byte[] sharedKey,
                                       LTPAPrivateKey rsaPrivateKey, LTPAPublicKey rsaPublicKey,
                                       MLDSAPrivateKey pqcPrivateKey, MLDSAPublicKey pqcPublicKey) {
        if (tokens == null || tokens.length == 0) {
            return new Token[0];
        }
        
        Token[] converted = new Token[tokens.length];
        int successCount = 0;
        
        for (int i = 0; i < tokens.length; i++) {
            try {
                converted[i] = LTPAToken3Factory.convertToken(
                    tokens[i], targetAlgorithm, sharedKey,
                    rsaPrivateKey, rsaPublicKey,
                    pqcPrivateKey, pqcPublicKey
                );
                successCount++;
            } catch (Exception e) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isWarningEnabled()) {
                    Tr.warning(tc, "Failed to convert token " + i + ": " + e.getMessage());
                }
                converted[i] = null;
            }
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isInfoEnabled()) {
            Tr.info(tc, "Converted " + successCount + " of " + tokens.length + " tokens to " + targetAlgorithm);
        }
        
        return converted;
    }
    
    /**
     * Analyze a key file and provide migration recommendations
     * 
     * @param keyFilePath Path to key file
     * @param password Key file password
     * @return Migration analysis report
     */
    public static MigrationAnalysis analyzeKeyFile(String keyFilePath, @Sensitive String password) {
        try {
            Properties keys = loadKeyFile(keyFilePath, password);
            
            if (keys == null) {
                return new MigrationAnalysis(false, false, false, "Failed to load key file", null);
            }
            
            boolean hasRSA = LTPAPQCKeyUtil.hasTraditionalKeys(keys);
            boolean hasPQC = LTPAPQCKeyUtil.hasPQCKeys(keys);
            boolean needsMigration = hasRSA && !hasPQC;
            
            String recommendation;
            MigrationStrategy recommendedStrategy;
            
            if (hasPQC) {
                recommendation = "Key file already contains PQC keys. No migration needed.";
                recommendedStrategy = null;
            } else if (hasRSA) {
                recommendation = "Key file contains only RSA keys. Recommend adding PQC keys for quantum resistance.";
                recommendedStrategy = MigrationStrategy.ADD_PQC_KEYS;
            } else {
                recommendation = "Key file does not contain valid keys. Generate new hybrid keys.";
                recommendedStrategy = MigrationStrategy.GENERATE_HYBRID;
            }
            
            return new MigrationAnalysis(hasRSA, hasPQC, needsMigration, recommendation, recommendedStrategy);
            
        } catch (Exception e) {
            return new MigrationAnalysis(false, false, false, "Error analyzing key file: " + e.getMessage(), null);
        }
    }
    
    /**
     * Migration analysis result
     */
    public static class MigrationAnalysis {
        private final boolean hasRSAKeys;
        private final boolean hasPQCKeys;
        private final boolean needsMigration;
        private final String recommendation;
        private final MigrationStrategy recommendedStrategy;
        
        public MigrationAnalysis(boolean hasRSAKeys, boolean hasPQCKeys, boolean needsMigration,
                                String recommendation, MigrationStrategy recommendedStrategy) {
            this.hasRSAKeys = hasRSAKeys;
            this.hasPQCKeys = hasPQCKeys;
            this.needsMigration = needsMigration;
            this.recommendation = recommendation;
            this.recommendedStrategy = recommendedStrategy;
        }
        
        public boolean hasRSAKeys() {
            return hasRSAKeys;
        }
        
        public boolean hasPQCKeys() {
            return hasPQCKeys;
        }
        
        public boolean needsMigration() {
            return needsMigration;
        }
        
        public String getRecommendation() {
            return recommendation;
        }
        
        public MigrationStrategy getRecommendedStrategy() {
            return recommendedStrategy;
        }
        
        @Override
        public String toString() {
            return "MigrationAnalysis[" +
                   "hasRSA=" + hasRSAKeys +
                   ", hasPQC=" + hasPQCKeys +
                   ", needsMigration=" + needsMigration +
                   ", recommendation='" + recommendation + "'" +
                   ", recommendedStrategy=" + recommendedStrategy +
                   "]";
        }
    }
    
    /**
     * Generate a migration report for a key file
     * 
     * @param keyFilePath Path to key file
     * @param password Key file password
     * @return Human-readable migration report
     */
    public static String generateMigrationReport(String keyFilePath, @Sensitive String password) {
        MigrationAnalysis analysis = analyzeKeyFile(keyFilePath, password);
        
        StringBuilder report = new StringBuilder();
        report.append("=== LTPA Key File Migration Report ===\n");
        report.append("File: ").append(keyFilePath).append("\n");
        report.append("Date: ").append(new java.util.Date()).append("\n\n");
        
        report.append("Current State:\n");
        report.append("  RSA Keys Present: ").append(analysis.hasRSAKeys() ? "YES" : "NO").append("\n");
        report.append("  PQC Keys Present: ").append(analysis.hasPQCKeys() ? "YES" : "NO").append("\n");
        report.append("  Migration Needed: ").append(analysis.needsMigration() ? "YES" : "NO").append("\n\n");
        
        report.append("Recommendation:\n");
        report.append("  ").append(analysis.getRecommendation()).append("\n");
        
        if (analysis.getRecommendedStrategy() != null) {
            report.append("  Recommended Strategy: ").append(analysis.getRecommendedStrategy()).append("\n");
        }
        
        report.append("\n=== End of Report ===\n");
        
        return report.toString();
    }
}

// Made with Bob
