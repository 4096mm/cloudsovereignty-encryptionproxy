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
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component("VaultTransitAdapter")
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class VaultTransitAdapter implements ICryptoAdapter {

    private static final Logger log = LoggerFactory.getLogger(VaultTransitAdapter.class);

    private String endpoint;
    private String token;

    private final CryptoService cryptoService;

    public VaultTransitAdapter(CryptoService cryptoService) {
        this.cryptoService = cryptoService;
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

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to encrypt data: " + response.body());
            }

            var responseBody = response.body();

            // Log metadata for each encryption operation
            for (CryptoTask operation : data) {
                log.info("Encrypted data with metadata: {}", operation.getMetadata());
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

    @Override
    public String[] decryptBatch(List<CryptoTask> data) {
        try {
            String payload = buildPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint + "/decrypt"))
                    .header("X-Vault-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to decrypt data: " + response.body());
            }

            throw new UnsupportedOperationException("Not implemented");
        } catch (Exception e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

    @Override
    public String[] rewrapBatch(List<CryptoTask> data) {
        try {
            String payload = buildPayload(data);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint + "/rewrap"))
                    .header("X-Vault-Token", token)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload))
                    .build();

            HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Failed to rewrap data: " + response.body());
            }

            throw new UnsupportedOperationException("Not implemented");
        } catch (Exception e) {
            throw new RuntimeException("Error during rewrapping", e);
        }
    }

    private String buildPayload(List<CryptoTask> data) {
        StringBuilder payloadBuilder = new StringBuilder();
        payloadBuilder.append("{\"batch_input\":[");

        for (int i = 0; i < data.size(); i++) {
            payloadBuilder.append("{\"plaintext\":\"")
                    .append(cryptoService.getCryptoTaskPayload(data.get(i)))
                    .append("\"}");

            if (i < data.size() - 1) {
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