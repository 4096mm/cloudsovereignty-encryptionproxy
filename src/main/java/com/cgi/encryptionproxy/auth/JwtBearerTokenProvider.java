package com.cgi.encryptionproxy.auth;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.*;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.*;

import java.net.URI;
import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Generic JWT Bearer token provider (RFC 7523)
 */
public class JwtBearerTokenProvider {

    private static final long requestJwtLifetimeSeconds = 300; // JWT lifetime for token request

    private final URI tokenEndpoint;
    private final RSAPrivateKey privateKey;
    private final String keyId;

    private final Map<String, BearerAccessToken> cache = new ConcurrentHashMap<>();

    public JwtBearerTokenProvider(URI tokenEndpoint, RSAPrivateKey privateKey, String keyId) {
        this.tokenEndpoint = tokenEndpoint;
        this.privateKey = privateKey;
        this.keyId = keyId;
    }

    /**
     * Request access token with given claims
     * 
     * @param iss      issuer claim
     * @param sub      subject claim
     * @param audience audience claim
     */
    public BearerAccessToken getToken(String iss, String sub, String audience) {
        try {
            String cacheKey = iss + "|" + sub + "|" + audience;
            BearerAccessToken cached = cache.get(cacheKey);
            if (cached != null && cached.isValid())
                return cached;

            SignedJWT jwt = createJwt(iss, sub, audience);

            JWTBearerGrant grant = new JWTBearerGrant(jwt);
            TokenRequest request = new TokenRequest(tokenEndpoint, grant);

            HTTPResponse httpResponse = request.toHTTPRequest().send();
            TokenResponse response = TokenResponse.parse(httpResponse);

            if (!response.indicatesSuccess()) {
                throw new RuntimeException("Token request failed: " + response.toErrorResponse().getErrorObject());
            }

            AccessToken token = response.toSuccessResponse().getTokens().getAccessToken();

            if (cache.containsKey(cacheKey)) {
                BearerAccessToken existing = cache.get(cacheKey);
                existing.setToken(token.getValue(), token.getLifetime());
                return existing;
            }

            BearerAccessToken newToken = new BearerAccessToken(token.getValue(), token.getLifetime());
            cache.put(cacheKey, newToken);
            return newToken;
        } catch (Exception e) {
            throw new RuntimeException("Failed to obtain access token", e);
        }
    }

    private SignedJWT createJwt(String iss, String sub, String audience) {
        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(iss)
                .subject(sub)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(requestJwtLifetimeSeconds)))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512)
                .keyID(keyId)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new RSASSASigner(privateKey));
        } catch (JOSEException e) {
            throw new RuntimeException("Error signing JWT", e);
        }
        return jwt;
    }
}