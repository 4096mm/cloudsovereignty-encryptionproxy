package com.cgi.encryptionproxy.auth;

public class BearerAccessToken {

    private static final long EXPIRY_SAFETY_MARGIN_SECONDS = 60; // Refresh token 60 seconds before actual expiry

    private String token;
    private long expiresAt; // epoch seconds

    public BearerAccessToken(String token, long expiresInSeconds) {
        this.token = token;
        this.expiresAt = System.currentTimeMillis() / 1000 + expiresInSeconds - EXPIRY_SAFETY_MARGIN_SECONDS;
    }

    public String getToken() {
        return token;
    }

    public boolean isValid() {
        return System.currentTimeMillis() / 1000 < expiresAt;
    }

    public void setToken(String token, long expiresInSeconds) {
        this.token = token;
        this.expiresAt = System.currentTimeMillis() / 1000 + expiresInSeconds - EXPIRY_SAFETY_MARGIN_SECONDS;
    }

}
