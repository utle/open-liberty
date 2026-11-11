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
package io.openliberty.security.rest.jwt.fat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.config.ServerConfiguration;
import com.ibm.websphere.simplicity.config.Variable;
import com.ibm.websphere.simplicity.log.Log;

import componenttest.annotation.AllowedFFDC;
import componenttest.annotation.Server;
import componenttest.annotation.SkipForRepeat;
import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;

/**
 * Key rotation: the public key file named by the jwkEndpointUrl of the JMXConnectorRESTConsumer is replaced
 * with the public key of a new key pair while the server is running.
 *
 * The jwtConsumer keeps the key it read from the file until its configuration is reloaded, so overwriting
 * the file is not enough on its own. Each rotation in this test replaces the file and then changes the
 * rotation.clockSkew variable in server.xml, which reloads the jwtConsumer. After the reload, tokens signed with
 * the new private key must be accepted and tokens signed with the previous private key must be rejected,
 * without restarting the server.
 *
 * Every request uses a token with a new jti claim because the jwtConsumer accepts a given jti only once.
 *
 * The testLiveRotation tests replace the key file and do NOT reload the jwtConsumer, like a node agent that
 * rotates its key while the server runs. The keys and the tokens must carry a kid: a kid that is not in the
 * cached key set makes the server read the key file again. A token without a kid is verified with the single key
 * that is cached, so the new key is never picked up.
 */
@RunWith(FATRunner.class)
@Mode(TestMode.LITE)
@SkipForRepeat({ SkipForRepeat.EE9_OR_LATER_FEATURES })
public class RestJwtKeyRotationFATTest {

    private static final Class<?> c = RestJwtKeyRotationFATTest.class;

    private static final String ISSUER = "IBMJMXConnectorRESTIssuer";
    private static final String AUDIENCE = "IBMJMXConnectorREST";

    private static final String ROTATION_VARIABLE = "rotation.clockSkew";
    private static final String CLOCK_SKEW_A = "60s";
    private static final String CLOCK_SKEW_B = "61s";

    private static final String ORIGINAL_KID = "original-key";
    private static final String NEW_KID = "new-key";

    // JWKSet.Stale is 1 minute; wait a little longer so the removed key is stale
    private static final long STALE_WAIT_MS = 62 * 1000;

    @Server("RestJwtKeyRotationServer")
    public static LibertyServer server;

    private static KeyPairGenerator generator;
    private static File keyFile;
    private static boolean useClockSkewB;

    // The private key whose public key is currently in the key file
    private static PrivateKey currentKey;

    @BeforeClass
    public static void setUp() throws Exception {
        String methodName = "setUp";

        // Generate the key pairs at run time so that no private key is checked in.
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        // Must be the file named by jwkEndpointUrl in the RestJwtKeyRotationServer server.xml
        keyFile = new File(server.getServerRoot() + "/resources/security/jwtPublic.pem");
        keyFile.getParentFile().mkdirs();
        currentKey = writeNewKeyPair();

        Log.info(c, methodName, "Starting RestJwtKeyRotationServer with the jwkEndpointUrl file " + keyFile.getAbsolutePath());
        server.startServer();
        assertNotNull("IBMJMXConnectorREST application was not ready",
                      server.waitForStringInLog("SRVE0242I.*IBMJMXConnectorREST"));
        assertNotNull("Default HTTPS endpoint did not start", server.waitForDefaultHTTPEndpointSSLStart());
    }

    @AfterClass
    public static void tearDown() throws Exception {
        try {
            server.stopServer();
        } finally {
            if (keyFile != null) {
                keyFile.delete();
            }
        }
    }

    /**
     * Each test starts from a freshly rotated key, so that the tests do not depend on their order.
     */
    @Before
    public void startWithNewKey() throws Exception {
        rotateKey();
    }

    /**
     * After the rotation the token signed with the new private key is accepted and the token signed with the
     * previous private key is rejected.
     */
    @Test
    @AllowedFFDC({ "org.jose4j.jwt.consumer.InvalidJwtSignatureException" })
    public void testRotatedKey_NewKeyAccepted_OldKeyRejected() throws Exception {
        PrivateKey oldKey = currentKey;
        assertEquals("Expected 200 OK for a token signed with the current key before the rotation",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(oldKey)).getResponseCode());

        PrivateKey newKey = rotateKey();

        assertEquals("Expected 200 OK for a token signed with the new key after the rotation",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(newKey)).getResponseCode());
        assertRejected(createRs256Token(oldKey), "a token signed with the previous key");
    }

    /**
     * The key can be rotated more than once. Only the key that is in the file at the moment of the request is
     * trusted, so neither of the two earlier keys is accepted any more.
     */
    @Test
    @AllowedFFDC({ "org.jose4j.jwt.consumer.InvalidJwtSignatureException" })
    public void testRotatedTwice_OnlyLatestKeyAccepted() throws Exception {
        PrivateKey firstKey = currentKey;
        PrivateKey secondKey = rotateKey();
        PrivateKey thirdKey = rotateKey();

        assertEquals("Expected 200 OK for a token signed with the latest key",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(thirdKey)).getResponseCode());
        assertRejected(createRs256Token(secondKey), "a token signed with the key before the latest");
        assertRejected(createRs256Token(firstKey), "a token signed with the oldest key");
    }

    /**
     * A rejected token is a 401 because of the signature, not because the server is unable to
     * authenticate anyone: a token signed with the current key still works afterwards.
     */
    @Test
    @AllowedFFDC({ "org.jose4j.jwt.consumer.InvalidJwtSignatureException" })
    public void testRotatedKey_RejectedTokenDoesNotAffectValidTokens() throws Exception {
        PrivateKey oldKey = currentKey;
        PrivateKey newKey = rotateKey();

        assertRejected(createRs256Token(oldKey), "a token signed with the previous key");
        assertEquals("Expected 200 OK for a token signed with the new key after a rejected request",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(newKey)).getResponseCode());
    }

    /**
     * Live rotation of a JWKS file with a grace period, without any configuration change. The file holds the
     * original key, then the original and the new key (grace period), then only the new key. The keys and the
     * tokens carry a kid. A token with a kid that is not in the cached key set is a cache miss, so the file is
     * read again and the new key is picked up.
     * <p>
     * A key that was removed from the file stays in the cache until it is older than JWKSet.Stale (1 minute) and
     * the file is read again, so this test does not expect the removed key to be rejected. See
     * testLiveRotation_JwksWithKid_RemovedKeyRejectedAfterStaleTime.
     */
    @Test
    public void testLiveRotation_JwksWithKid_NewKeyAcceptedWithoutConfigChange() throws Exception {
        KeyPair originalPair = generator.generateKeyPair();
        KeyPair newPair = generator.generateKeyPair();

        writeJwksWithKids(new String[] { ORIGINAL_KID }, originalPair);
        assertEquals("Expected 200 OK for a token with kid " + ORIGINAL_KID + " when it is the only key in the JWKS file",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(originalPair.getPrivate(), ORIGINAL_KID)).getResponseCode());

        writeJwksWithKids(new String[] { ORIGINAL_KID, NEW_KID }, originalPair, newPair);
        assertEquals("Expected 200 OK for a token with kid " + ORIGINAL_KID + " during the grace period",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(originalPair.getPrivate(), ORIGINAL_KID)).getResponseCode());

        writeJwksWithKids(new String[] { NEW_KID }, newPair);
        assertEquals("Expected 200 OK for a token with kid " + NEW_KID + " after the original key was removed from the JWKS file",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(newPair.getPrivate(), NEW_KID)).getResponseCode());
    }

    /**
     * The original key is replaced by a new key in the JWKS file while the server runs and the configuration is
     * NOT changed. The removed key stays cached until it is older than JWKSet.Stale (1 minute) and the key file is
     * read again. A request with the new kid is a cache miss, so it reads the file and drops the stale original
     * key. After that a token with the original kid must be rejected.
     */
    @Test
    @AllowedFFDC({ "org.jose4j.jwt.consumer.InvalidJwtSignatureException" })
    public void testLiveRotation_JwksWithKid_RemovedKeyRejectedAfterStaleTime() throws Exception {
        KeyPair originalPair = generator.generateKeyPair();
        KeyPair newPair = generator.generateKeyPair();

        // Only the original key is cached by the first request, so the request with the new kid is a cache miss
        writeJwksWithKids(new String[] { ORIGINAL_KID }, originalPair);
        assertEquals("Expected 200 OK for a token with kid " + ORIGINAL_KID + " when it is the only key in the JWKS file",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(originalPair.getPrivate(), ORIGINAL_KID)).getResponseCode());

        writeJwksWithKids(new String[] { NEW_KID }, newPair);
        Thread.sleep(STALE_WAIT_MS);

        assertEquals("Expected 200 OK for a token with kid " + NEW_KID + " after the original key was removed from the JWKS file",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(newPair.getPrivate(), NEW_KID)).getResponseCode());
        assertRejected(createRs256Token(originalPair.getPrivate(), ORIGINAL_KID),
                       "a token with kid " + ORIGINAL_KID + " more than a minute after it was removed from the JWKS file");
    }

    /**
     * Negative test: the same live rotation, but the keys and the tokens have no kid. The first request caches
     * the single key from the file. A token without a kid is verified with that cached key and never causes the
     * file to be read again, so a token signed with the new key is rejected until the jwtConsumer is reloaded.
     * This is why the keys of a rotating key file must have a kid.
     */
    @Test
    @AllowedFFDC({ "org.jose4j.jwt.consumer.InvalidJwtSignatureException" })
    public void testLiveRotation_JwksWithoutKid_NewKeyRejectedWithoutConfigChange() throws Exception {
        KeyPair originalPair = generator.generateKeyPair();
        KeyPair newPair = generator.generateKeyPair();

        writeJwksWithKids(new String[] { null }, originalPair);
        assertEquals("Expected 200 OK for a token without a kid when the original key is the only key in the JWKS file",
                     HttpURLConnection.HTTP_OK, sendRequest(createRs256Token(originalPair.getPrivate(), null)).getResponseCode());

        writeJwksWithKids(new String[] { null }, newPair);
        assertRejected(createRs256Token(newPair.getPrivate(), null),
                       "a token without a kid, signed with the new key, because the old key is still cached and the key file is not read again");
    }

    /**
     * Replaces the public key in the file with the public key of a new key pair and reloads the jwtConsumer.
     *
     * @return the private key that matches the public key now in the file
     */
    private static PrivateKey rotateKey() throws Exception {
        currentKey = writeNewKeyPair();
        reloadJwtConsumer();
        return currentKey;
    }

    private static PrivateKey writeNewKeyPair() throws Exception {
        KeyPair pair = generator.generateKeyPair();
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                     + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pair.getPublic().getEncoded())
                     + "\n-----END PUBLIC KEY-----\n";
        Files.write(keyFile.toPath(), pem.getBytes(StandardCharsets.US_ASCII));
        return pair.getPrivate();
    }

    /**
     * Replaces the content of the key file with a JWKS that holds the public keys of the given key pairs. Each key
     * gets the kid at the same position in kids; a null kid leaves the key without a kid. The server configuration
     * is not touched.
     */
    private static void writeJwksWithKids(String[] kids, KeyPair... pairs) throws Exception {
        JsonWebKeySet jwks = new JsonWebKeySet();
        for (int i = 0; i < pairs.length; i++) {
            RsaJsonWebKey jwk = new RsaJsonWebKey((RSAPublicKey) pairs[i].getPublic());
            if (kids[i] != null) {
                jwk.setKeyId(kids[i]);
            }
            jwk.setUse("sig");
            jwk.setAlgorithm(AlgorithmIdentifiers.RSA_USING_SHA256);
            jwks.addJsonWebKey(jwk);
        }
        Files.write(keyFile.toPath(), jwks.toJson().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Changes the variable that the clockSkew of the jwtConsumer refers to, which makes the server reload the
     * jwtConsumer and drop the public key that it cached from the key file.
     */
    private static void reloadJwtConsumer() throws Exception {
        ServerConfiguration config = server.getServerConfiguration();
        Variable variable = config.getVariables().getBy("name", ROTATION_VARIABLE);
        assertNotNull("The " + ROTATION_VARIABLE + " variable is missing from the server.xml", variable);
        useClockSkewB = !useClockSkewB;
        variable.setValue(useClockSkewB ? CLOCK_SKEW_B : CLOCK_SKEW_A);

        server.setMarkToEndOfLog();
        server.updateServerConfiguration(config);
        assertFalse("The server configuration update was not completed",
                    server.waitForConfigUpdateInLogUsingMark(Collections.<String> emptySet()).isEmpty());
    }

    private static void assertRejected(String token, String description) throws Exception {
        server.setMarkToEndOfLog();
        assertEquals("Expected 401 Unauthorized for " + description,
                     HttpURLConnection.HTTP_UNAUTHORIZED, sendRequest(token).getResponseCode());
        assertNotNull("RestJwtTAI did not report an error validating " + description,
                      server.waitForStringInTraceUsingMark("Error validating JWT token"));
    }

    private static String createRs256Token(PrivateKey key) throws Exception {
        return createRs256Token(key, null);
    }

    private static String createRs256Token(PrivateKey key, String kid) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject("adminUser");
        claims.setStringListClaim("groups", Collections.singletonList("liberty-admin"));
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        if (kid != null) {
            jws.setKeyIdHeaderValue(kid);
        }
        jws.setKey(key);
        return jws.getCompactSerialization();
    }

    private static HttpURLConnection sendRequest(String bearerToken) throws Exception {
        URL url = new URL("https", server.getHostname(), server.getHttpSecondarySecurePort(), FATSuite.REST_MBEANS_ENDPOINT);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, new TrustManager[] { new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        } }, new java.security.SecureRandom());
        conn.setSSLSocketFactory(sc.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);
        conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
        conn.connect();
        return conn;
    }
}
