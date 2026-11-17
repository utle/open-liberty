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
package io.openliberty.security.rest.jwt.tai;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtSignatureException;
import org.jose4j.jwx.JsonWebStructure;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.WebTrustAssociationException;
import com.ibm.websphere.security.WebTrustAssociationFailedException;
import com.ibm.websphere.security.jwt.InvalidClaimException;
import com.ibm.websphere.security.jwt.JwtConsumer;
import com.ibm.websphere.security.jwt.JwtToken;
import com.ibm.ws.ffdc.annotation.FFDCIgnore;
import com.ibm.ws.security.SecurityService;
import com.ibm.ws.security.authentication.filter.AuthenticationFilter;
import com.ibm.ws.security.jwt.config.JwtConsumerConfig;
import com.ibm.ws.security.jwt.config.MpConfigProperties;
import com.ibm.ws.security.common.jwk.utils.JsonUtils;
import com.ibm.ws.webcontainer.security.WebRequest;
import com.ibm.ws.webcontainer.security.internal.TAIAuthenticator;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;
import com.ibm.wsspi.kernel.service.utils.ConcurrentServiceReferenceMap;
import com.ibm.wsspi.security.tai.TAIResult;
import com.ibm.wsspi.security.tai.TrustAssociationInterceptor;

@Component(service = { TrustAssociationInterceptor.class },
           immediate = true,
           configurationPolicy = ConfigurationPolicy.IGNORE,
           name = "restJwtTAI",
           property = { "service.vendor=IBM",
                        "type=restJwtTAI",
                        "id=RestJwtTAI",
                        "TAIName=RestJwtTAI",
                        "invokeBeforeSSO:Boolean=true",
                        "disableLtpaCookie:Boolean=true" })
public class RestJwtTAI implements TrustAssociationInterceptor {

    private static final TraceComponent tc = Tr.register(RestJwtTAI.class, TraceConstants.TRACE_GROUP, TraceConstants.MESSAGE_BUNDLE);

    public static final String KEY_SERVICE_PID = "service.pid";
    public static final String KEY_SECURITY_SERVICE = "securityService";
    public static final String KEY_FILTER = "authFilter";
    public static final String DEFAULT_AUTH_FILTER_ID = "defaultRestJwtAuthFilter";
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String BEARER_PREFIX = "Bearer ";
    public static final String LTPA_COOKIE_NAME = "LtpaToken2";
    private static final String ISSUER_CLAIM = "iss";
    private static final String AUDIENCE_CLAIM = "aud";
    public static final String REST_AUDIENCES = "IBMJMXConnectorREST";
    public static final String REST_ISSUER = "IBMJMXConnectorRESTIssuer";

    public static final String KEY_JWT_CONSUMER_CONFIG = "jwtConsumerConfig";
    public static final String DEFAULT_JWT_CONSUMER_ID = "JMXConnectorRESTConsumer";

    static final String MSG_STALE_KEY_NO_KID = "REST_JWT_STALE_KEY_NO_KID";
    static final String MSG_KID_NOT_IN_KEY_FILE = "REST_JWT_KID_NOT_IN_KEY_FILE";

    // The key file version and the messages that were logged for it, so that a message is logged once for each version
    // of the key file and not for every failed request
    private static String loggedKeyFileVersion;
    private static final List<String> loggedMessages = new ArrayList<String>();

    public static final String PREFIX_REST_ENDPOINT = "/IBMJMXConnectorREST";

    static final AtomicServiceReference<SecurityService> securityServiceRef = new AtomicServiceReference<SecurityService>(KEY_SECURITY_SERVICE);
    static protected final ConcurrentServiceReferenceMap<String, AuthenticationFilter> authFilterServiceRef = new ConcurrentServiceReferenceMap<String, AuthenticationFilter>(KEY_FILTER);
    static protected final ConcurrentServiceReferenceMap<String, JwtConsumerConfig> jwtConsumerConfigRef = new ConcurrentServiceReferenceMap<String, JwtConsumerConfig>(KEY_JWT_CONSUMER_CONFIG);
    /*
 	<jwtConsumer id="JMXConnectorRESTConsumer" 
   		signatureAlgorithm="RS256"
   		issuer="IBMJMXConnectorRESTIssuer" 
   		audiences="IBMJMXConnectorREST"
   		jwkEnabled="true"
   		jwkEndpointUrl="file:///<profileRoot>/etc/node.jwks"
	</jwtConsumer>
    */
    
    
    @Reference(service = JwtConsumerConfig.class, name = KEY_JWT_CONSUMER_CONFIG, policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MULTIPLE, policyOption = ReferencePolicyOption.GREEDY)
    protected void setJwtConsumerConfig(ServiceReference<JwtConsumerConfig> ref) {
        String id = (String) ref.getProperty("id");
        synchronized (jwtConsumerConfigRef) {
            jwtConsumerConfigRef.putReference(id, ref);
        }
    }

    protected void updatedJwtConsumerConfig(ServiceReference<JwtConsumerConfig> ref) {
        String id = (String) ref.getProperty("id");
        synchronized (jwtConsumerConfigRef) {
            jwtConsumerConfigRef.putReference(id, ref);
        }
    }

    protected void unsetJwtConsumerConfig(ServiceReference<JwtConsumerConfig> ref) {
        String id = (String) ref.getProperty("id");
        synchronized (jwtConsumerConfigRef) {
            jwtConsumerConfigRef.removeReference(id, ref);
        }
    }

    @Reference(service = SecurityService.class, name = KEY_SECURITY_SERVICE, policy = ReferencePolicy.DYNAMIC, policyOption = ReferencePolicyOption.GREEDY)
    public void setSecurityService(ServiceReference<SecurityService> reference) {
        securityServiceRef.setReference(reference);
    }

    public void unsetSecurityService(ServiceReference<SecurityService> reference) {
        securityServiceRef.unsetReference(reference);
    }

    @Reference(service = AuthenticationFilter.class, name = KEY_FILTER, policy = ReferencePolicy.DYNAMIC, cardinality = ReferenceCardinality.MULTIPLE, policyOption = ReferencePolicyOption.RELUCTANT)
    protected void setAuthFilter(ServiceReference<AuthenticationFilter> ref) {
        String pid = (String) ref.getProperty(KEY_SERVICE_PID);
        synchronized (authFilterServiceRef) {
            authFilterServiceRef.putReference(pid, ref);
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "setAuthFilter pid: " + pid);
        }
    }

    protected void updatedAuthFilter(ServiceReference<AuthenticationFilter> ref) {
        String pid = (String) ref.getProperty(KEY_SERVICE_PID);
        synchronized (authFilterServiceRef) {
            authFilterServiceRef.putReference(pid, ref);
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "updatedAuthFilter pid: " + pid);
        }
    }

    protected void unsetAuthFilter(ServiceReference<AuthenticationFilter> ref) {
        String pid = (String) ref.getProperty(KEY_SERVICE_PID);
        synchronized (authFilterServiceRef) {
            authFilterServiceRef.removeReference(pid, ref);
        }
        if (tc.isDebugEnabled()) {
            Tr.debug(tc, "unsetAuthFilter pid: " + pid);
        }
    }

    public static AuthenticationFilter getAuthFilter(String pid) {
        return authFilterServiceRef.getService(pid);
    }

    public static Iterator<AuthenticationFilter> getAuthFilters() {
        return authFilterServiceRef.getServices();
    }

    @Activate
    protected void activate(ComponentContext cc, Map<String, Object> props) {
        synchronized (authFilterServiceRef) {
            authFilterServiceRef.activate(cc);
        }
        synchronized (jwtConsumerConfigRef) {
            jwtConsumerConfigRef.activate(cc);
        }
        securityServiceRef.activate(cc);
    }

    @Modified
    protected void modified(ComponentContext cc, Map<String, Object> props) {
        // Do nothing
    }

    @Deactivate
    protected void deactivate(ComponentContext cc) {
        synchronized (authFilterServiceRef) {
            authFilterServiceRef.deactivate(cc);
        }
        synchronized (jwtConsumerConfigRef) {
            jwtConsumerConfigRef.deactivate(cc);
        }
        securityServiceRef.deactivate(cc);
    }

    @Override
    public boolean isTargetInterceptor(HttpServletRequest request) throws WebTrustAssociationException {
        // 1. Verify this request targets the REST admin endpoint
        if (!isTargetRestAdminRequest(request)) {
            return false;
        }

        // 2. Check if authentication filter accepts this request
        if (!isAcceptedByAuthFilter(request)) {
            return false;
        }

        // 3. If the request carries an LTPA cookie, do not target it
        if (hasLtpaCookie(request)) {
            return false;
        }

        // 4. Verify that the request carries a Bearer JWT token in the Authorization header, and that the
        //    token was issued for the REST admin endpoint (REST issuer and REST audience). A Bearer token
        //    from any other issuer or for any other audience is not processed by this TAI.
        String token = getBearerToken(request);
        if (token != null && !token.isEmpty()) {
            return isRestJwt(token);
        }

        return false;
    }

    @Override
    public TAIResult negotiateValidateandEstablishTrust(HttpServletRequest request, HttpServletResponse response) throws WebTrustAssociationFailedException {
        String token = getBearerToken(request);
        if (token == null || token.isEmpty()) {
            return getResultForMissingToken(request);
        }

        return validateJwtAndCreateResult(token);
    }

    @FFDCIgnore({ Exception.class, IllegalArgumentException.class })
    protected TAIResult validateJwtAndCreateResult(@Sensitive String token) throws WebTrustAssociationFailedException {
        JwtToken jwtToken = null;
        try {
            jwtToken = parseJwt(token);
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Error validating JWT token: " + e.getMessage(), e);
            }
            boolean signatureInvalid = hasCause(e, InvalidJwtSignatureException.class);
            if (signatureInvalid || hasCause(e, InvalidClaimException.class)) {
                reportKidProblem(token, signatureInvalid);
            }
            return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
        }

        if (jwtToken == null) {
            return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
        }

        // The node agent builds the JWT with a server or user access ID as the subject and plain group names. Either the
        // subject or a group must be an access ID to give the realm; otherwise the token is rejected.
        RestJwtMappingHelper mappingHelper;
        try {
            mappingHelper = new RestJwtMappingHelper(jwtToken);
        } catch (IllegalArgumentException e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Error mapping JWT token claims: " + e.getMessage());
            }
            return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
        }
        String username = mappingHelper.getUsername();
        if (username == null || username.isEmpty()) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Could not extract username from JWT token claims");
            }
            return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
        }

        Subject subject = mappingHelper.createSubject();
        return TAIResult.create(HttpServletResponse.SC_OK, username, subject);
    }

    private static boolean hasCause(Throwable e, Class<? extends Throwable> type) {
        for (Throwable t = e; t != null; t = (t.getCause() == t ? null : t.getCause())) {
            if (type.isInstance(t)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Called after the jwtConsumer rejected the signature of a token (the signature check failed), or failed with a claim
     * exception, which includes the case that it could not find a key for the token. The exceptions of the jwtConsumer do
     * not say that the cause can be a kid that is missing or does not match, so this logs the root cause instead. The
     * node agent sends a request about every few seconds, so a message is logged once for each version of the key file.
     *
     * @param signatureInvalid true if the jwtConsumer rejected the signature, false if it failed with a claim exception
     */
    @FFDCIgnore({ Exception.class })
    protected void reportKidProblem(@Sensitive String token, boolean signatureInvalid) {
        try {
            File keyFile = getKeyFile(jwtConsumerConfigRef.getService(DEFAULT_JWT_CONSUMER_ID));
            if (keyFile == null) {
                return;
            }
            String version = keyFile.getPath() + ":" + keyFile.lastModified();
            KidProblem problem = findKidProblem(token, keyFile, signatureInvalid);
            if (problem == null) {
                return;
            }
            synchronized (loggedMessages) {
                if (!version.equals(loggedKeyFileVersion)) {
                    loggedKeyFileVersion = version;
                    loggedMessages.clear();
                }
                if (loggedMessages.contains(problem.messageKey)) {
                    return;
                }
                loggedMessages.add(problem.messageKey);
            }
            Tr.error(tc, problem.messageKey, problem.args);
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Unable to find out if a missing kid caused the failure: " + e.getMessage());
            }
        }
    }

    /** A message key and the arguments of the message that describe why a kid does not match a key in the key file */
    static class KidProblem {
        final String messageKey;
        final Object[] args;

        KidProblem(String messageKey, Object... args) {
            this.messageKey = messageKey;
            this.args = args;
        }
    }

    /**
     * @return the file that the jwkEndpointUrl of the jwtConsumer points to, or null if it is not set or is not a file
     */
    protected File getKeyFile(JwtConsumerConfig config) throws Exception {
        if (config == null) {
            return null;
        }
        String location = config.getJwkEndpointUrl();
        if (location == null || location.trim().isEmpty()) {
            return null;
        }
        location = location.trim();
        if (location.startsWith("file:")) {
            return new File(new URI(location).getPath());
        }
        return location.startsWith("http") ? null : new File(location);
    }

    /**
     * Compares the kid of the token with the kids of the keys in the key file. Only a JSON Web Key set can have a kid, so
     * a PEM public key file and a file that cannot be read give null.
     * <ul>
     * <li>The token has no kid, the jwtConsumer rejected the signature, and the signature is valid for a key in the file:
     * the jwtConsumer used the single key that it cached earlier, which is out of date. REST_JWT_STALE_KEY_NO_KID.
     * A claim failure, such as an expired token, is not a kid problem.</li>
     * <li>The token has no kid and the signature is not valid for any key in the file: not a kid problem, null.</li>
     * <li>The token has a kid and no key in the file has it: REST_JWT_KID_NOT_IN_KEY_FILE. This is also the case when the
     * keys in the file have no kid.</li>
     * <li>The token has a kid and a key in the file has it: null.</li>
     * </ul>
     */
    @FFDCIgnore({ Exception.class })
    protected KidProblem findKidProblem(@Sensitive String token, File keyFile, boolean signatureInvalid) {
        try {
            if (!keyFile.isFile()) {
                return null;
            }
            String content = new String(Files.readAllBytes(keyFile.toPath()), StandardCharsets.UTF_8).trim();
            if (!content.startsWith("{")) {
                return null;
            }
            JsonWebStructure structure = JsonWebStructure.fromCompactSerialization(token);
            if (!(structure instanceof JsonWebSignature)) {
                return null;
            }
            JsonWebSignature jws = (JsonWebSignature) structure;
            String tokenKid = jws.getKeyIdHeaderValue();
            List<JsonWebKey> keys = new JsonWebKeySet(content).getJsonWebKeys();

            if (tokenKid != null) {
                List<String> keyKids = new ArrayList<String>();
                for (JsonWebKey key : keys) {
                    if (tokenKid.equals(key.getKeyId())) {
                        return null;
                    }
                    keyKids.add(key.getKeyId() == null ? "(none)" : key.getKeyId());
                }
                return new KidProblem(MSG_KID_NOT_IN_KEY_FILE, keyFile.getPath(), tokenKid, keyKids);
            }
            if (signatureInvalid) {
                for (JsonWebKey key : keys) {
                    if (isSignedWith(jws, key)) {
                        return new KidProblem(MSG_STALE_KEY_NO_KID, keyFile.getPath());
                    }
                }
            }
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Unable to compare the kid of the token with the keys in " + keyFile.getPath() + ": " + e.getMessage());
            }
        }
        return null;
    }

    @FFDCIgnore({ Exception.class })
    private boolean isSignedWith(JsonWebSignature jws, JsonWebKey key) {
        try {
            jws.setKey(key.getKey());
            return jws.verifySignature();
        } catch (Exception e) {
            // The key does not fit the algorithm of the token, so this key did not sign it
            return false;
        }
    }

    /**
     * Validates the token with the jwtConsumer. If the JMXConnectorRESTConsumer has a jwkEndpointUrl configured,
     * for example jwkEndpointUrl="file:///path/to/jwk", the public key is read from that location;
     * otherwise the key comes from the jwtConsumer keystore configuration.
     */
    protected JwtToken parseJwt(@Sensitive String token) throws Exception {
        JwtConsumerConfig config = jwtConsumerConfigRef.getService(DEFAULT_JWT_CONSUMER_ID);
        return config.getConsumerUtils().parseJwt(token, config);
    }

    /**
     * @return properties that point the jwtConsumer at the key location given by its jwkEndpointUrl,
     *         or null if the jwtConsumer or its jwkEndpointUrl is not configured
     */
    protected MpConfigProperties getKeyLocationProperties(JwtConsumerConfig config) {
        if (config == null) {
            return null;
        }
        String location = config.getJwkEndpointUrl();
        if (location == null || location.trim().isEmpty()) {
            return null;
        }
        MpConfigProperties mpProps = new MpConfigProperties();
        mpProps.put(MpConfigProperties.KEY_LOCATION, location.trim());
        return mpProps;
    }

    protected boolean isTargetRestAdminRequest(HttpServletRequest request) {
        if (request == null) {
            return false;
        }

        String requestURI = request.getRequestURI();
        if (requestURI != null && requestURI.contains(PREFIX_REST_ENDPOINT)) {
            return true;
        }

        StringBuffer requestURL = request.getRequestURL();
        if (requestURL != null && requestURL.toString().contains(PREFIX_REST_ENDPOINT)) {
            return true;
        }

        String servletPath = request.getServletPath();
        if (servletPath != null && servletPath.contains(PREFIX_REST_ENDPOINT)) {
            return true;
        }

        String contextPath = request.getContextPath();
        if (contextPath != null && contextPath.contains(PREFIX_REST_ENDPOINT)) {
            return true;
        }

        return false;
    }

    protected boolean isAcceptedByAuthFilter(HttpServletRequest request) {
        // First check the default auth filter
        AuthenticationFilter defaultFilter = getAuthFilter(DEFAULT_AUTH_FILTER_ID);
        if (defaultFilter != null) {
            return defaultFilter.isAccepted(request);
        }

        // If other auth filters are configured, check if any accepts
        Iterator<AuthenticationFilter> filters = getAuthFilters();
        if (filters != null && filters.hasNext()) {
            while (filters.hasNext()) {
                AuthenticationFilter filter = filters.next();
                if (filter.isAccepted(request)) {
                    return true;
                }
            }
            return false;
        }

        // If no auth filter service is available yet, default to allowing admin requests
        return true;
    }

    /**
     * Reads the claims of the token without validating it and checks that the issuer is the REST issuer and
     * that the audience contains the REST audience. The signature and the rest of the claims are validated
     * later by the jwtConsumer.
     *
     * @return true if the token is issued by the REST issuer for the REST audience, false otherwise
     */
    @FFDCIgnore({ Exception.class })
    protected boolean isRestJwt(@Sensitive String token) {
        try {
            String payload = JsonUtils.getPayload(token);
            if (payload == null) {
                return false;
            }
            Map<String, Object> claims = JsonUtils.claimsFromJsonObject(JsonUtils.decodeFromBase64String(payload));
            if (!REST_ISSUER.equals(claims.get(ISSUER_CLAIM))) {
                if (tc.isDebugEnabled()) {
                    Tr.debug(tc, "The token was not issued by " + REST_ISSUER);
                }
                return false;
            }
            Object audience = claims.get(AUDIENCE_CLAIM);
            boolean hasRestAudience = REST_AUDIENCES.equals(audience) || (audience instanceof Collection && ((Collection<?>) audience).contains(REST_AUDIENCES));
            if (!hasRestAudience && tc.isDebugEnabled()) {
                Tr.debug(tc, "The token is not for the audience " + REST_AUDIENCES);
            }
            return hasRestAudience;
        } catch (Exception e) {
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "Unable to read the token claims: " + e.getMessage());
            }
            return false;
        }
    }

    protected boolean hasLtpaCookie(HttpServletRequest request) {
        if (request == null) {
            return false;
        }
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (LTPA_COOKIE_NAME.equals(cookie.getName())) {
                    return true;
                }
            }
        }
        return false;
    }

    public String getBearerToken(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String authHeader = request.getHeader(HEADER_AUTHORIZATION);
        if (authHeader != null && authHeader.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = authHeader.substring(BEARER_PREFIX.length()).trim();
            if (!token.isEmpty()) {
                return token;
            }
        }
        return null;
    }

    protected TAIResult getResultForMissingToken(HttpServletRequest request) throws WebTrustAssociationFailedException {
        if (isUnprotectedRequest(request)) {
            return TAIResult.create(HttpServletResponse.SC_CONTINUE);
        }
        return TAIResult.create(HttpServletResponse.SC_UNAUTHORIZED);
    }

    protected boolean isUnprotectedRequest(HttpServletRequest request) {
        if (request != null) {
            WebRequest webRequest = (WebRequest) request.getAttribute(TAIAuthenticator.WEB_REQUEST_ATTRIBUTE_NAME);
            if (webRequest != null) {
                return webRequest.isUnprotectedURI();
            }
        }
        return false;
    }

    @Override
    public int initialize(Properties props) throws WebTrustAssociationFailedException {
        return 0;
    }

    @Override
    public String getVersion() {
        return "1.0";
    }

    @Override
    public String getType() {
        return this.getClass().getName();
    }

    @Override
    public void cleanup() {
        // Nothing to clean up
    }
}
