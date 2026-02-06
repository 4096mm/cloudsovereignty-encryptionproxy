package com.cgi.encryptionproxy.adapters;

import com.cgi.encryptionproxy.util.ProviderRegistry.ConfigurableAdapter;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.databind.ObjectMapper;

public class VaultTransitAdapter implements ICryptoAdapter, ConfigurableAdapter {

    private static final Logger logger = LoggerFactory.getLogger(VaultTransitAdapter.class);

    private String endpoint;
    private String token;

    @Override
    public void configure(Map<String, String> parameters) {
        this.endpoint = parameters.get("endpoint");
        this.token = parameters.get("token");

        if (endpoint == null || token == null) {
            throw new IllegalStateException("VaultTransitAdapter requires 'endpoint' and 'token' parameters.");
        }
    }

    @Override
    public String[] encryptBatch(CryptoOperation[] data) {
        try {
            String payload = buildBatchPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint + "/encrypt/" + data[0].getKeyName()))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to encrypt data: " + response.body());
            }

            var responseBody = response.body();

            // Log metadata for each encryption operation
            for (CryptoOperation operation : data) {
                logger.info("Encrypted data with metadata: {}", operation.getMetadataAsJson());
            }

            return parseBatchResponse(responseBody);
        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    private String buildBatchPayload(CryptoOperation[] data) {
        List<String> batchInput = List.of(data).stream()
            .map(op -> String.format("{\"plaintext\":\"%s\", \"key_version\":%s}", op.getEncryptionPayload(), op.getKeyVersion()))
            .collect(Collectors.toList());

        return String.format("{\"batch_input\":[%s]}", String.join(",", batchInput));
    }

    @Override
    public String decryptBatch(CryptoOperation[] data) {
        try {
            String payload = buildPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint + "/v1/" + transitPath + "/decrypt"))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to decrypt data: " + response.body());
            }

            return response.body();
        } catch (Exception e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

    @Override
    public String rewrapBatch(CryptoOperation[] data) {
        try {
            String payload = buildPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint + "/v1/" + transitPath + "/rewrap"))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to rewrap data: " + response.body());
            }

            return response.body();
        } catch (Exception e) {
            throw new RuntimeException("Error during rewrapping", e);
        }
    }

    private String buildPayload(CryptoOperation[] data) {
        StringBuilder payloadBuilder = new StringBuilder();
        payloadBuilder.append("{\"batch_input\":[");

        for (int i = 0; i < data.length; i++) {
            payloadBuilder.append("{\"plaintext\":\"")
                .append(data[i].getEncryptionPayload())
                .append("\"}");

            if (i < data.length - 1) {
                payloadBuilder.append(",");
            }
        }

        payloadBuilder.append("]}");
        return payloadBuilder.toString();
    }

    private String[] parseBatchResponse(String responseBody) {
        try {
            var mapper = new ObjectMapper();
            var rootNode = mapper.readTree(responseBody);
            var dataNode = rootNode.path("data");
            var batchResults = dataNode.path("batch_results");

            String[] results = new String[batchResults.size()];
            for (int i = 0; i < batchResults.size(); i++) {
                var resultNode = batchResults.get(i);
                results[i] = resultNode.path("ciphertext").asString();
            }
            return results;
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse batch response", e);
        }
    }
}