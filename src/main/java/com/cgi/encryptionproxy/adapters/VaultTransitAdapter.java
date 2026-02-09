package com.cgi.encryptionproxy.adapters;

import com.cgi.encryptionproxy.service.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

// ToDo: This whole thing is pretty crude - cleanup needed...

@Component("VaultTransitAdapter")
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class VaultTransitAdapter implements ICryptoAdapter {

    private static final Logger log = LoggerFactory.getLogger(VaultTransitAdapter.class);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private String endpoint;
    private String token;

    private final CryptoService cryptoService;
    private final ObjectMapper objectMapper;

    public VaultTransitAdapter(CryptoService cryptoService, ObjectMapper objectMapper) {
        this.cryptoService = cryptoService;
        this.objectMapper = objectMapper;
    }

    @Override
    public void configure(Map<String, String> parameters) {
        this.endpoint = parameters.get("endpoint");
        this.token = parameters.get("token");

        if (endpoint == null || token == null) {
            throw new IllegalStateException("VaultTransitAdapter requires 'endpoint' and 'token' parameters.");
        }
    }

    @Override
    public String[] encryptBatch(List<CryptoTask> data) {
        try {
            String vaultUrl = String.format("%s/encrypt/%s",
                    endpoint.replaceAll("/$", ""),
                    data.getFirst().getKeyName());

            String payload = buildBatchPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(vaultUrl))
                    .header("X-Vault-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to encrypt data: " + response.body());
            }

            var responseBody = response.body();

            // Log metadata for each encryption operation
            for (CryptoTask operation : data) {
                log.info("Encrypted data with metadata: {}", objectMapper.writeValueAsString(operation.getMetadata()));
            }

            return parseBatchResponse(responseBody);
        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }


    }

    private String buildBatchPayload(Collection<CryptoTask> data) {
        List<String> batchInput = data.stream()
                .map(op -> String.format("{\"plaintext\":\"%s\", \"key_version\":%s}", cryptoService.getCryptoTaskPayload(op), op.getKeyVersion()))
                .toList();

        return String.format("{\"batch_input\":[%s]}", String.join(",", batchInput));
    }

    private String buildDecryptBatchPayload(Collection<CryptoTask> data) {
        List<String> batchInput = data.stream()
                .map(op -> String.format("{\"ciphertext\":\"%s\", \"key_version\":%s}", op.getDataBase64(), op.getKeyVersion()))
                .toList();

        return String.format("{\"batch_input\":[%s]}", String.join(",", batchInput));
    }

    @Override
    public String[] decryptBatch(List<CryptoTask> data) {
        try {
            String vaultUrl = String.format("%s/decrypt/%s",
                    endpoint.replaceAll("/$", ""),
                    data.getFirst().getKeyName());

            String payload = buildDecryptBatchPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(vaultUrl))
                    .header("X-Vault-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to decrypt data: " + response.body());
            }

            var responseBody = response.body();

            return parseBatchDecryptResponse(responseBody);
        } catch (Exception e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

    @Override
    public String[] rewrapBatch(List<CryptoTask> data) {
        throw new UnsupportedOperationException("Not implemented");
    }

    private String[] parseBatchResponse(String responseBody) {
        try {
            var mapper = objectMapper;
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

    private String[] parseBatchDecryptResponse(String responseBody) {
        try {
            var rootNode = objectMapper.readTree(responseBody);
            var dataNode = rootNode.path("data");
            var batchResults = dataNode.path("batch_results");

            String[] results = new String[batchResults.size()];

            for (int i = 0; i < batchResults.size(); i++) {
                var resultNode = batchResults.get(i);
                String encoded = resultNode.path("plaintext").asText("");
                String decodedPlaintext = new String(
                        Base64.getDecoder().decode(encoded),
                        StandardCharsets.UTF_8
                );

                // split on first ';' only
                String[] parts = decodedPlaintext.split(";", 2);

                // first argument → returned
                results[i] = parts[0];

                if (parts.length > 1 && !parts[1].isBlank()) {
                    try {
                        Object metadata = objectMapper.readTree(parts[1]);
                        log.info("Decrypted data with metadata: {}", metadata);
                    } catch (Exception ignored) {
                        // optional: log if invalid JSON, but don't fail parsing
                    }
                }
            }

            return results;
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse batch response", e);
        }
    }
}