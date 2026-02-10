package com.cgi.encryptionproxy.adapters;

import java.util.Base64;

import tools.jackson.databind.ObjectMapper;

public record EncryptOperation(String provider, String keyName, Integer keyVersion, String plaintext, Object metadata) {
    public String toEncryptionPayload(ObjectMapper objectMapper) {
        if (objectMapper == null) {
            throw new IllegalArgumentException("ObjectMapper cannot be null");
        }

        String metadata = "";
        if (metadata() != null) {
            try {
                metadata = objectMapper.writeValueAsString(metadata());
            } catch (Exception e) {
                throw new RuntimeException("Failed to serialize metadata", e);
            }
        }

        String payload = plaintext() + ";" + metadata;
        return Base64.getEncoder().encodeToString(payload.getBytes());
    }
}
