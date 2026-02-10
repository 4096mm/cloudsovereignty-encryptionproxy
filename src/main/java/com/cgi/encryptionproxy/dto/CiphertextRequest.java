package com.cgi.encryptionproxy.dto;

import com.cgi.encryptionproxy.adapters.DecryptOperation;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Used for decryption requests
 * Each item in "data" contains "ciphertext" and optional "metadata"
 */
public class CiphertextRequest {

    private String keyProvider;
    private String keyName;
    private Integer keyVersion;
    private Object data;
    private Object metadata;

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

    public List<DecryptOperation> toCryptoTasks(String provider) {
        if (data instanceof String s) {
            return List.of(DecryptOperation.fromString(provider, keyName, s));
        }

        if (data instanceof List<?> list) {
            return list.stream().map(item -> {
                if (item instanceof Map<?, ?> map) {
                    String ciphertext = (String) map.get("ciphertext");
                    return DecryptOperation.fromString(provider, keyName, ciphertext);
                }
                throw new IllegalArgumentException("List items must be objects with 'ciphertext'");
            }).collect(Collectors.toList());
        }

        throw new IllegalArgumentException("Invalid data format: Expected String or List");
    }
}
