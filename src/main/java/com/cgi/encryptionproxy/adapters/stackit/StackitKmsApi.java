package com.cgi.encryptionproxy.adapters.stackit;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.cgi.encryptionproxy.auth.BearerAccessToken;

public class StackitKmsApi {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String baseUrl;
    private final BearerAccessToken token;
    private final String projectId;
    private final String regionId;
    private final String keyRingId;

    public StackitKmsApi(String endpoint, String projectId, String regionId, String keyRingId, BearerAccessToken token,
            ObjectMapper objectMapper) {
        if (endpoint == null || projectId == null || regionId == null || keyRingId == null || token == null) {
            throw new IllegalArgumentException("endpoint, projectId, regionId, keyRingId, and token must not be null");
        }

        this.baseUrl = endpoint.replaceAll("/$", "") +
                "/v1/projects/" + projectId +
                "/regions/" + regionId +
                "/keyrings/" + keyRingId;
        this.projectId = projectId;
        this.regionId = regionId;
        this.keyRingId = keyRingId;
        this.token = token;
        this.objectMapper = objectMapper;

        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /**
     * Validates that a keyId is a valid UUID format
     */
    private void validateUuid(String keyId) {
        if (keyId == null
                || !keyId.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) {
            throw new IllegalArgumentException("keyId must be a valid UUID: " + keyId);
        }
    }

    /**
     * Gets the latest active version number for a key
     */
    public Integer getLatestKeyVersion(String keyId) {
        validateUuid(keyId);

        try {
            String url = baseUrl + "/keys/" + keyId + "/versions";

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + token.getToken())
                    .header("Content-Type", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Stackit list versions failed: " + response.body());
            }

            return parseLatestVersion(response.body());
        } catch (Exception e) {
            throw new RuntimeException("Failed to get latest key version", e);
        }
    }

    /**
     * Encrypts multiple data items individually (Stackit doesn't support batch
     * operations)
     */
    public List<EncryptResult> encryptBatch(String keyId, Integer versionNumber, List<EncryptRequest> requests) {
        validateUuid(keyId);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<EncryptResult>> futures = requests.stream()
                    .map(req -> executor.submit(() -> encryptSingle(keyId, versionNumber, req)))
                    .toList();

            List<EncryptResult> results = new ArrayList<>();
            for (Future<EncryptResult> future : futures) {
                try {
                    results.add(future.get()); // blocks until the single request finishes
                } catch (ExecutionException e) {
                    throw new RuntimeException("Error encrypting request", e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Thread interrupted while encrypting", e);
                }
            }

            return results;
        }
    }

    /**
     * Decrypts multiple data items individually (Stackit doesn't support batch
     * operations)
     */
    public List<DecryptResult> decryptBatch(String keyId, List<DecryptRequest> requests) {
        validateUuid(keyId);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<DecryptResult>> futures = requests.stream()
                    .map(req -> executor.submit(() -> decryptSingle(keyId, req.versionNumber(), req)))
                    .toList();

            List<DecryptResult> results = new ArrayList<>();
            for (Future<DecryptResult> future : futures) {
                try {
                    results.add(future.get()); // blocks until the single request finishes
                } catch (ExecutionException e) {
                    throw new RuntimeException("Error decrypting request", e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException("Thread interrupted while decrypting", e);
                }
            }
            return results;
        }
    }

    private EncryptResult encryptSingle(String keyId, Integer versionNumber, EncryptRequest request) {
        try {
            String url = baseUrl + "/keys/" + keyId + "/versions/" + versionNumber + "/encrypt";

            var payload = objectMapper.createObjectNode();
            payload.put("data", base64(request.plaintext()));

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + token.getToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                    .build();

            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Stackit encrypt failed: " + response.body());
            }

            JsonNode data = objectMapper.readTree(response.body()).path("data");
            String ciphertext = data.asString("");

            return new EncryptResult(ciphertext);
        } catch (Exception e) {
            throw new RuntimeException("Stackit encrypt failed", e);
        }
    }

    private DecryptResult decryptSingle(String keyId, Integer versionNumber, DecryptRequest request) {
        try {
            String url = baseUrl + "/keys/" + keyId + "/versions/" + versionNumber + "/decrypt";

            var payload = objectMapper.createObjectNode();
            payload.put("data", request.ciphertext());

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .header("Authorization", "Bearer " + token.getToken())
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                    .build();

            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException(
                        "Stackit decrypt failed: " + response.body() + " for ciphertext: " + request.ciphertext());
            }

            JsonNode data = objectMapper.readTree(response.body()).path("data");
            String encoded = data.asString("");
            String decoded = new String(Base64.getDecoder().decode(encoded));

            return new DecryptResult(decoded);
        } catch (Exception e) {
            throw new RuntimeException("Stackit decrypt failed", e);
        }
    }

    private Integer parseLatestVersion(String body) {
        try {
            JsonNode versions = objectMapper.readTree(body).path("versions");

            Integer latestVersion = null;

            for (JsonNode versionNode : versions) {
                String state = versionNode.path("state").asText("");
                boolean disabled = versionNode.path("disabled").asBoolean(false);

                // Only consider active, enabled versions
                if ("active".equals(state) && !disabled) {
                    Integer number = versionNode.path("number").asInt();
                    if (latestVersion == null || number > latestVersion) {
                        latestVersion = number;
                    }
                }
            }

            if (latestVersion == null) {
                throw new RuntimeException("No active version found for key");
            }

            return latestVersion;
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse version list", e);
        }
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes());
    }

    public record EncryptRequest(String plaintext) {
    }

    public record DecryptRequest(String ciphertext, Integer versionNumber) {
    }

    public record EncryptResult(String ciphertext) {
    }

    public record DecryptResult(String plaintext) {
    }

    public record Version(Integer number, String state, boolean disabled) {
    }
}
