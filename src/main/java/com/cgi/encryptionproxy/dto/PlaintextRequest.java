package com.cgi.encryptionproxy.dto;

import com.cgi.encryptionproxy.adapters.EncryptOperation;
import com.cgi.encryptionproxy.util.ValidationUtils;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Used for encryption requests
 * Each item in "data" contains "plaintext" and optional "metadata"
 */
public class PlaintextRequest {

    private String keyProvider;
    private String keyName;
    private Integer keyVersion;
    private Object data; // String or List<Map<String,Object>>
    private Object metadata;

    // Getters / setters
    public String getKeyProvider() {
        return keyProvider;
    }

    public void setKeyProvider(String keyProvider) {
        this.keyProvider = keyProvider;
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

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }

    public Object getMetadata() {
        return metadata;
    }

    public void setMetadata(Object metadata) {
        this.metadata = metadata;
    }

    public List<EncryptOperation> toCryptoTasks(String provider) {
        if (data instanceof String b64) {
            ValidationUtils.requireBase64Encoded(b64);
            return List.of(new EncryptOperation(provider, keyName, keyVersion, b64, metadata));
        }

        if (data instanceof List<?> list) {
            return list.stream().map(item -> {
                if (item instanceof Map<?, ?> map) {
                    String plaintext = (String) map.get("plaintext");
                    Object itemMetadata = map.getOrDefault("metadata", null);
                    ValidationUtils.requireBase64Encoded(plaintext);
                    return new EncryptOperation(provider, keyName, keyVersion, plaintext, itemMetadata);
                }
                throw new IllegalArgumentException("List items must be objects with 'plaintext'");
            }).collect(Collectors.toList());
        }

        throw new IllegalArgumentException("Invalid data format: Expected String or List");
    }
}
