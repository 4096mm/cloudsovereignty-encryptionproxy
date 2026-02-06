package com.cgi.encryptionproxy.controller;

import org.springframework.web.bind.annotation.*;
import com.cgi.encryptionproxy.adapters.CryptoOperation;
import com.cgi.encryptionproxy.adapters.ICryptoAdapter;
import com.cgi.encryptionproxy.util.ProviderRegistry;
import com.cgi.encryptionproxy.util.ValidationUtils;

import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class EncryptionController {

    private final ProviderRegistry providerRegistry;

    public EncryptionController(ProviderRegistry providerRegistry) {
        this.providerRegistry = providerRegistry;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<List<EncryptionResponse>> encrypt(@RequestBody EncryptionRequest request) {
        CryptoOperation[] operations = request.getDataList();

        ICryptoAdapter adapter = providerRegistry.getProvider(request.getKeyProvider());

        var results = adapter.encryptBatch(operations);

        List<EncryptionResponse> responses = List.of(results).stream()
            .map(EncryptionResponse::new)
            .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    public static class EncryptionRequest {
        private String keyProvider;
        private String keyName;
        private Integer keyVersion;
        private Object data;
        private Object metadata;

        public EncryptionRequest() {
        }

        public EncryptionRequest(String keyProvider, String keyName, Integer keyVersion, Object data, Object metadata) {
            this.keyProvider = keyProvider;
            this.keyName = keyName;
            this.keyVersion = keyVersion;
            this.data = data;
            this.metadata = metadata;
        }

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

        public CryptoOperation[] getDataList() {
            if (data instanceof String) {
                // Single Base64-encoded string
                ValidationUtils.requireBase64Encoded((String) data);
                return new CryptoOperation[]{new CryptoOperation(keyName, keyVersion, (String) data, metadata)};
            } else if (data instanceof List) {
                // List of objects with plaintext and metadata
                return ((List<?>) data).stream().map(item -> {
                    if (item instanceof Map) {
                        Map<?, ?> map = (Map<?, ?>) item;
                        String plaintext = (String) map.get("plaintext");
                        ValidationUtils.requireBase64Encoded(plaintext);
                        Object itemMetadata = map.get("metadata");
                        return new CryptoOperation(keyName, keyVersion, plaintext, itemMetadata);
                    } else {
                        throw new IllegalArgumentException("Invalid data format. List items must be objects with 'plaintext' and 'metadata'.");
                    }
                }).toArray(CryptoOperation[]::new);
            } else {
                throw new IllegalArgumentException("Invalid data format. Must be a string or a list of objects.");
            }
        }
    }

    public static class EncryptionResponse {
        private String encrypted;

        public EncryptionResponse() {
        }

        public EncryptionResponse(String encrypted) {
            this.encrypted = encrypted;
        }

        public String getEncrypted() {
            return encrypted;
        }

        public void setEncrypted(String encrypted) {
            this.encrypted = encrypted;
        }
    }
}