package com.cgi.encryptionproxy.adapters.stackit;

import java.net.URI;
import java.security.interfaces.RSAPrivateKey;

import com.cgi.encryptionproxy.auth.BearerAccessToken;
import com.cgi.encryptionproxy.auth.JwtBearerTokenProvider;
import com.cgi.encryptionproxy.util.PemUtils;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Stackit-specific JWT bearer token provider.
 * Accepts JSON string containing credentials:
 * {
 *   "credentials": {
 *     "iss", "sub", "aud", "kid", "privateKey"
 *   }
 * }
 * Automatically uses default Stackit token endpoint.
 */
public class StackitJwtTokenProvider {

    private static final URI DEFAULT_TOKEN_ENDPOINT =
            URI.create("https://service-account.api.stackit.cloud/token");

    private final JwtBearerTokenProvider provider;
    private final String iss;
    private final String sub;
    private final String audience;

    public StackitJwtTokenProvider(String serviceAccountJson) {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode creds = mapper.readTree(serviceAccountJson).path("credentials");

        this.iss = creds.path("iss").asString();
        this.sub = creds.path("sub").asString();
        this.audience = creds.path("aud").asString();
        String keyId = creds.path("kid").asString();
        String privateKeyPem = creds.path("privateKey").asString();

        RSAPrivateKey privateKey = PemUtils.parsePrivateKey(privateKeyPem);

        // 10 minutes token lifetime
        this.provider = new JwtBearerTokenProvider(DEFAULT_TOKEN_ENDPOINT, privateKey, keyId);
    }

    public BearerAccessToken getAccessToken() {
        return provider.getToken(iss, sub, audience);
    }
}
