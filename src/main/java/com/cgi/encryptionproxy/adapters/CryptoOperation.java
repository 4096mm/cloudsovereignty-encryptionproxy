package com.cgi.encryptionproxy.adapters;

import java.util.Base64;

import tools.jackson.databind.ObjectMapper;

public class CryptoOperation {

    private String keyName;
    private Integer keyVersion;
    private Object metadata;

    private String dataBase64;

    public CryptoOperation() {
    }

    public CryptoOperation(String keyName, Integer keyVersion, String data, Object metadata) {
        this.keyName = keyName;
        this.keyVersion = keyVersion;
        this.metadata = metadata;
        this.dataBase64 = data;
    }

    public static CryptoOperation fromEncryptedPayload(String payload) {
        try {
            String decodedPayload = new String(Base64.getDecoder().decode(payload));
            String[] parts = decodedPayload.split(";", 3);
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid payload format");
            }
            String dataBase64 = parts[0];
            Integer keyVersion = Integer.parseInt(parts[1]);
            Object metadata = null;
            if (parts.length == 3 && !parts[2].isEmpty()) {
                metadata = new ObjectMapper().readValue(parts[2], Object.class);
            }
            return new CryptoOperation(null, keyVersion, dataBase64, metadata);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse encryption payload", e);
        }
    }

    /**
     * Get the encryption payload in base64 encoded format
     * @return String base64 encoded payload
     */
    public String getEncryptionPayload() {        
        String payload = dataBase64 + ";" + serializeMetadata();
        return Base64.getEncoder().encodeToString(payload.getBytes());
    }

    private String serializeMetadata() {
        if (metadata == null) {
            return "";
        }
        try {
            return new ObjectMapper().writeValueAsString(metadata);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize metadata", e);
        }
    }

    public String getKeyName() {
        return keyName;
    }

    public void setKeyName(String keyName) {
        this.keyName = keyName;
    }

    public Integer getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(Integer keyVersion) {
        this.keyVersion = keyVersion;
    }

    public Object getMetadata() {
        return metadata;
    }

    public String getMetadataAsJson() {
        if (metadata == null) {
            return "{}";
        }
        try {
            return new ObjectMapper().writeValueAsString(metadata);
        } catch (Exception e) {
            throw new RuntimeException("Failed to serialize metadata", e);
        }
    }

    public void setMetadata(Object metadata) {
        this.metadata = metadata;
    }

    public String getDataBase64() {
        return dataBase64;
    }
}
