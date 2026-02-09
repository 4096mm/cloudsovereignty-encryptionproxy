package com.cgi.encryptionproxy.controller;

import com.cgi.encryptionproxy.adapters.CryptoTask;
import com.cgi.encryptionproxy.adapters.ICryptoAdapter;
import com.cgi.encryptionproxy.service.ProviderRegistryService;
import com.cgi.encryptionproxy.util.ValidationUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1")
public class EncryptionController {

    private final ProviderRegistryService providerRegistryService;

    public EncryptionController(ProviderRegistryService providerRegistryService) {
        this.providerRegistryService = providerRegistryService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<List<EncryptionResponse>> encrypt(@RequestBody EncryptionRequest request) {
        List<CryptoTask> operations = request.toCryptoTasks();

        ICryptoAdapter adapter = providerRegistryService.getProvider(request.getKeyProvider());

        var results = adapter.encryptBatch(operations);

        List<EncryptionResponse> responses = Stream.of(results)
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

        public String getKeyProvider() {
            return keyProvider;
        }

        /**
         * A lightweight, internal implementation of CryptoTask.
         * Using a record (Java 16+) makes this extremely memory-efficient and
         * removes boilerplate.
         */
        private record InternalTask(
                String keyName,
                Integer keyVersion,
                String dataBase64,
                Object metadata
        ) implements CryptoTask {
            @Override public String getKeyName() { return keyName; }
            @Override public Integer getKeyVersion() { return keyVersion; }
            @Override public String getDataBase64() { return dataBase64; }
            @Override public Object getMetadata() { return metadata; }
        }

        /**
         * Transforms the request into a list of tasks without copying
         * large underlying data strings.
         */
        public List<CryptoTask> toCryptoTasks() {
            if (data instanceof String b64Data) {
                ValidationUtils.requireBase64Encoded(b64Data);
                return List.of(new InternalTask(keyName, keyVersion, b64Data, metadata));
            }

            if (data instanceof List) {
                return ((List<?>) data).stream().map(item -> {
                    if (item instanceof Map<?, ?> map) {
                        String plaintext = (String) map.get("plaintext");
                        ValidationUtils.requireBase64Encoded(plaintext);
                        Object itemMetadata = map.getOrDefault("metadata", null);
                        return new InternalTask(keyName, keyVersion, plaintext, itemMetadata);
                    }
                    throw new IllegalArgumentException("List items must be objects with 'plaintext'");
                }).collect(Collectors.toList());
            }

            throw new IllegalArgumentException("Invalid data format: Expected String or List");
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