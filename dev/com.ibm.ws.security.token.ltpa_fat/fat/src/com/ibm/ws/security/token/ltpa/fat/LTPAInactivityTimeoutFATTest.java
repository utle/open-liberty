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
package com.ibm.ws.security.token.ltpa.fat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.kernel.boot.cmdline.Utils;

import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.impl.LibertyServerFactory;

/**
 * FAT tests for the LTPA inactivity timeout feature.
 *
 * Uses {@code serverTokenInactivity.xml}:
 *   expiration=10m, inactivityTimeout=1m, refreshThreshold=not set
 *
 * This isolates the hard-expiry-on-idle path from the proactive-refresh path:
 * - A token used within 1 minute remains valid.
 * - A token idle for more than 1 minute returns 401 even though absolute expiry
 *   (10 minutes) has not been reached.
 * - No proactive refresh occurs because refreshThreshold is not configured.
 * - The feature is completely inert when beta edition is disabled.
 */
@RunWith(FATRunner.class)
@Mode(TestMode.FULL)
public class LTPAInactivityTimeoutFATTest {

    private static final String APP_NAME = "ltpaTest";
    private static final String SERVLET_NAME = "LTPATestServlet";
    private static final String LTPA_COOKIE_NAME = "LtpaToken2";
    private static final Class<?> thisClass = LTPAInactivityTimeoutFATTest.class;
    private static LibertyServer server;

    // Config: inactivityTimeout=1m — wait 70s to go past the 1-minute idle window
    private static final long INACTIVITY_WAIT_MS = 70_000;
    // Small wait to confirm token is still valid (well within 1-minute window)
    private static final long FRESH_REQUEST_DELAY_MS = 2_000;

    @Rule
    public final TestWatcher logger = new TestWatcher() {
        @Override
        public void starting(Description description) {
            Log.info(thisClass, description.getMethodName(),
                     "\n=====================================\nStarting test: " +
                     description.getMethodName() + "\n=====================================");
        }

        @Override
        public void finished(Description description) {
            Log.info(thisClass, description.getMethodName(),
                     "\n=====================================\nFinished test: " +
                     description.getMethodName() + "\n=====================================");
        }
    };

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        // This feature is beta-only — skip when not running beta
        org.junit.Assume.assumeTrue(
            Utils.getInstallDir().toPath().resolve("lib/versions/openliberty.properties").toFile().exists() &&
            Boolean.getBoolean("com.ibm.ws.beta.edition"));

        server = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.refresh");
        server.copyFileToLibertyInstallRoot("lib/features", "internalFeatureForFat/ltpafattestlibertyinternals-1.0.mf");
        server.addInstalledAppForValidation(APP_NAME);
    }

    @Before
    public void setUp() throws Exception {
        server.setServerConfigurationFile("serverTokenInactivity.xml");
        server.startServer(true);
        server.waitForStringInLog("CWWKZ0001I.*" + APP_NAME);
    }

    @After
    public void tearDown() throws Exception {
        if (server != null && server.isStarted()) {
            server.stopServer();
        }
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        if (server != null && server.isStarted()) {
            server.stopServer();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 1 — token used within inactivity window stays valid, no new cookie
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * A token that is used again well within the inactivity window must remain
     * valid and must NOT produce a new Set-Cookie header (no proactive refresh
     * because refreshThreshold is not configured).
     */
    @Test
    public void testTokenRemainsValidWithinInactivityWindow() throws Exception {
        String testName = "testTokenRemainsValidWithinInactivityWindow";
        String url = getServletUrl();

        // Authenticate and get initial cookie
        HttpURLConnection conn1 = makeAuthenticatedRequest(url, null, "user1", "user1pwd");
        assertEquals("Initial authentication must succeed", 200, conn1.getResponseCode());
        String cookie = extractLTPACookie(conn1);
        assertNotNull("LTPA cookie must be set after authentication", cookie);
        conn1.disconnect();
        Log.info(thisClass, testName, "Initial cookie: " + LTPATestUtils.maskCookie(cookie));

        // Small delay — well within inactivity window
        Thread.sleep(FRESH_REQUEST_DELAY_MS);

        // SSO request — must succeed and must NOT issue a new cookie
        HttpURLConnection conn2 = makeRequestWithCookie(url, cookie);
        assertEquals("SSO request within inactivity window must succeed", 200, conn2.getResponseCode());
        String newCookie = extractLTPACookie(conn2);
        assertNull("No new cookie expected — refreshThreshold is not configured", newCookie);
        conn2.disconnect();
        Log.info(thisClass, testName, "Token still valid within inactivity window — no new cookie (expected)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 2 — token idle past inactivityTimeout returns 401
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * A token that has been idle for longer than {@code inactivityTimeout} must
     * be rejected (401 or 302 redirect) even though the absolute expiry (10 min)
     * has not been reached.
     */
    @Test
    public void testTokenExpiredAfterInactivityTimeout() throws Exception {
        String testName = "testTokenExpiredAfterInactivityTimeout";
        String url = getServletUrl();

        // Authenticate and get initial cookie
        HttpURLConnection conn1 = makeAuthenticatedRequest(url, null, "user1", "user1pwd");
        assertEquals("Initial authentication must succeed", 200, conn1.getResponseCode());
        String cookie = extractLTPACookie(conn1);
        assertNotNull("LTPA cookie must be set", cookie);
        conn1.disconnect();
        Log.info(thisClass, testName, "Received cookie: " + LTPATestUtils.maskCookie(cookie));

        // Wait past the 1-minute inactivity window (absolute expiry is 10 min away)
        Log.info(thisClass, testName, "Waiting " + INACTIVITY_WAIT_MS + "ms past inactivity timeout...");
        Thread.sleep(INACTIVITY_WAIT_MS);

        // Request with idle token — must be rejected
        HttpURLConnection conn2 = makeRequestWithCookie(url, cookie);
        int responseCode = conn2.getResponseCode();
        Log.info(thisClass, testName, "Response code with idle token: " + responseCode);
        conn2.disconnect();

        assertTrue("Idle token must be rejected (401 or 302), got: " + responseCode,
                   responseCode == 401 || responseCode == 302 || responseCode == 403);
        Log.info(thisClass, testName, "Idle token correctly rejected with status " + responseCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 3 — re-authentication after inactivity expiry issues a new token
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * After a token expires due to inactivity, the user can re-authenticate with
     * credentials and receive a fresh token that is distinct from the expired one.
     */
    @Test
    public void testReauthenticationAfterInactivityExpiry() throws Exception {
        String testName = "testReauthenticationAfterInactivityExpiry";
        String url = getServletUrl();

        // Initial authentication
        HttpURLConnection conn1 = makeAuthenticatedRequest(url, null, "user1", "user1pwd");
        String expiredCookie = extractLTPACookie(conn1);
        assertNotNull("Must receive initial cookie", expiredCookie);
        conn1.disconnect();

        // Let the token go idle
        Log.info(thisClass, testName, "Waiting " + INACTIVITY_WAIT_MS + "ms for inactivity expiry...");
        Thread.sleep(INACTIVITY_WAIT_MS);

        // Verify idle token is rejected
        HttpURLConnection conn2 = makeRequestWithCookie(url, expiredCookie);
        int rejectedCode = conn2.getResponseCode();
        conn2.disconnect();
        assertTrue("Idle token must be rejected before re-auth", rejectedCode == 401 || rejectedCode == 302 || rejectedCode == 403);

        // Re-authenticate with credentials — must succeed and issue a new cookie
        HttpURLConnection conn3 = makeAuthenticatedRequest(url, null, "user1", "user1pwd");
        assertEquals("Re-authentication must succeed", 200, conn3.getResponseCode());
        String newCookie = extractLTPACookie(conn3);
        assertNotNull("Must receive new cookie after re-authentication", newCookie);
        assertTrue("New cookie must differ from the expired one", !expiredCookie.equals(newCookie));
        conn3.disconnect();
        Log.info(thisClass, testName, "Re-authentication succeeded with new cookie: " + LTPATestUtils.maskCookie(newCookie));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Test 4 — inactivity window resets on each successful request
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * The inactivity deadline resets on each token use (each clone stamps a fresh
     * creationTime).  By making two requests separated by less than
     * {@code inactivityTimeout} each, the total elapsed time can exceed
     * {@code inactivityTimeout} while the token remains valid.
     *
     * Config: inactivityTimeout=1m, refreshThreshold=1m (both equal — refresh
     * fires immediately on first SSO validation, resetting the window).
     * We switch to serverTokenRefresh.xml for this test which has both configured.
     */
    @Test
    public void testInactivityWindowResetsOnTokenRefresh() throws Exception {
        String testName = "testInactivityWindowResetsOnTokenRefresh";

        // Switch to a config that has both inactivityTimeout AND refreshThreshold
        // so the token gets proactively cloned (resetting creationTime) on each request
        server.setMarkToEndOfLog();
        server.setServerConfigurationFile("serverTokenRefresh.xml");
        server.waitForConfigUpdateInLogUsingMark(null);
        Log.info(thisClass, testName, "Switched to serverTokenRefresh.xml (inactivityTimeout=2m, refreshThreshold=1m)");

        String url = getServletUrl();

        // Authenticate
        HttpURLConnection conn1 = makeAuthenticatedRequest(url, null, "user1", "user1pwd");
        assertEquals("Initial authentication must succeed", 200, conn1.getResponseCode());
        String cookie = extractLTPACookie(conn1);
        assertNotNull("Must receive initial cookie", cookie);
        conn1.disconnect();
        Log.info(thisClass, testName, "Initial cookie: " + LTPATestUtils.maskCookie(cookie));

        // Wait past refresh threshold (>1m remaining of 2m inactivity window = fires at ~61s)
        long waitMs = 65_000;
        Log.info(thisClass, testName, "Waiting " + waitMs + "ms to cross refresh threshold...");
        Thread.sleep(waitMs);

        // First SSO request — should trigger clone, resetting creationTime
        HttpURLConnection conn2 = makeRequestWithCookie(url, cookie);
        assertEquals("SSO request must succeed after waiting past threshold", 200, conn2.getResponseCode());
        String refreshedCookie = extractLTPACookie(conn2);
        conn2.disconnect();

        if (refreshedCookie != null) {
            Log.info(thisClass, testName, "Token was cloned — inactivity window reset");
            cookie = refreshedCookie;
        } else {
            Log.info(thisClass, testName, "No clone yet — token still within window");
        }

        // Wait another interval — if clone occurred, the window has reset, token must still be valid
        Log.info(thisClass, testName, "Waiting another " + waitMs + "ms...");
        Thread.sleep(waitMs);

        HttpURLConnection conn3 = makeRequestWithCookie(url, cookie);
        int responseCode = conn3.getResponseCode();
        conn3.disconnect();

        // With window reset, token should still be valid (200) or be refreshed again
        // Without reset, idle total would be ~130s > 120s inactivityTimeout → 401
        Log.info(thisClass, testName, "Response after second wait: " + responseCode);
        assertEquals("Token should still be valid after two waits if window was reset", 200, responseCode);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private String getServletUrl() {
        return "http://" + server.getHostname() + ":" + server.getHttpDefaultPort() +
               "/" + APP_NAME + "/" + SERVLET_NAME;
    }

    private HttpURLConnection makeAuthenticatedRequest(String urlString, String cookie,
                                                       String username, String password) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setInstanceFollowRedirects(false);
        if (cookie != null) {
            conn.setRequestProperty("Cookie", LTPA_COOKIE_NAME + "=" + cookie);
        }
        String basicAuth = "Basic " + java.util.Base64.getEncoder()
                               .encodeToString((username + ":" + password).getBytes());
        conn.setRequestProperty("Authorization", basicAuth);
        consumeResponse(conn);
        return conn;
    }

    private HttpURLConnection makeRequestWithCookie(String urlString, String cookie) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setDoInput(true);
        conn.setUseCaches(false);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestProperty("Cookie", LTPA_COOKIE_NAME + "=" + cookie);
        consumeResponse(conn);
        return conn;
    }

    private void consumeResponse(HttpURLConnection conn) {
        try {
            int code = conn.getResponseCode();
            InputStream is = (code >= 400) ? conn.getErrorStream() : conn.getInputStream();
            if (is != null) {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(is))) {
                    while (br.readLine() != null) { /* consume */ }
                }
            }
        } catch (IOException e) {
            Log.info(thisClass, "consumeResponse", "IOException: " + e.getMessage());
        }
    }

    private String extractLTPACookie(HttpURLConnection conn) {
        return LTPATestUtils.extractLTPACookie(conn);
    }
}
