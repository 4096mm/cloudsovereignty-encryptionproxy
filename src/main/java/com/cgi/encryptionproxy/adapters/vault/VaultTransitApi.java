package com.cgi.encryptionproxy.adapters.vault;


import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public class VaultTransitApi {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String endpoint;
    private final String token;

    public VaultTransitApi(String endpoint, String token, ObjectMapper objectMapper) {
        if (endpoint == null || token == null) {
            throw new IllegalArgumentException("endpoint and token must not be null");
        }

        this.endpoint = endpoint.replaceAll("/$", "");
        this.token = token;
        this.objectMapper = objectMapper;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    
    public List<EncryptResult> encryptBatch(String keyName, List<EncryptRequest> requests) {
        try {
            String url = endpoint + "/encrypt/" + keyName;
            String payload = buildEncryptPayload(requests);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("X-Vault-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Vault encrypt failed: " + response.body());
            }

            return parseCiphertexts(response.body());
        } catch (Exception e) {
            throw new RuntimeException("Vault encryptBatch failed", e);
        }
    }

    public List<DecryptResult> decryptBatch(String keyName, List<DecryptRequest> requests) {
        try {
            String url = endpoint + "/decrypt/" + keyName;
            String payload = buildDecryptPayload(requests);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("X-Vault-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response =
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Vault decrypt failed: " + response.body());
            }

            return parsePlaintexts(response.body());
        } catch (Exception e) {
            throw new RuntimeException("Vault decryptBatch failed", e);
        }
    }

    private String buildEncryptPayload(List<EncryptRequest> requests) throws Exception {
        var root = objectMapper.createObjectNode();
        var batch = root.putArray("batch_input");

        for (EncryptRequest req : requests) {
            var node = batch.addObject();
            node.put("plaintext", base64(req.plaintext()));
            if (req.keyVersion() != null) {
                node.put("key_version", req.keyVersion());
            }
        }

        return objectMapper.writeValueAsString(root);
    }

    private String buildDecryptPayload(List<DecryptRequest> requests) throws Exception {
        var root = objectMapper.createObjectNode();
        var batch = root.putArray("batch_input");

        for (DecryptRequest req : requests) {
            var node = batch.addObject();
            node.put("ciphertext", "vault:v" + req.keyVersion() + ":" + req.ciphertext());
        }

        return objectMapper.writeValueAsString(root);
    }

    private List<EncryptResult> parseCiphertexts(String body) throws Exception {
        JsonNode batchResults = objectMapper
                .readTree(body)
                .path("data")
                .path("batch_results");

        List<EncryptResult> results = new ArrayList<>(batchResults.size());

        for (JsonNode node : batchResults) {
            results.add(EncryptResult.fromKey(node.path("ciphertext").asString("")));
        }

        return results;
    }

    private List<DecryptResult> parsePlaintexts(String body) throws Exception {
        JsonNode batchResults = objectMapper
                .readTree(body)
                .path("data")
                .path("batch_results");

        List<DecryptResult> results = new ArrayList<>(batchResults.size());

        for (JsonNode node : batchResults) {
            String encoded = node.path("plaintext").asString("");
            String decoded = new String(
                    Base64.getDecoder().decode(encoded)
            );
            results.add(new DecryptResult(decoded));
        }

        return results;
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes());
    }

    public record EncryptRequest(String plaintext, Integer keyVersion) {}

    public record DecryptRequest(String ciphertext, Integer keyVersion) {
        public static DecryptRequest fromCiphertext(String ciphertext) {
            String[] parts = ciphertext.split(":", 3);
            if (parts.length != 3 || !parts[0].equals("vault")) {
                throw new IllegalArgumentException("Invalid ciphertext format");
            }
            return new DecryptRequest(parts[2], Integer.valueOf(parts[1].substring(1)));
        }
    }

    public record EncryptResult(String ciphertext, Integer keyVersion) {
        public static EncryptResult fromKey(String ciphertext) {
            String[] parts = ciphertext.split(":", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid ciphertext format");
            }
            return new EncryptResult(parts[2], Integer.valueOf(parts[1].substring(1)));
        }
    }

    public record DecryptResult(String plaintext) {
    }
}
