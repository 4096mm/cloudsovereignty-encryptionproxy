package com.cgi.encryptionproxy.adapters.stackit;

import com.cgi.encryptionproxy.adapters.BaseKmsAdapter;
import com.cgi.encryptionproxy.adapters.DecryptOperation;
import com.cgi.encryptionproxy.adapters.EncryptOperation;
import com.cgi.encryptionproxy.adapters.RewrapOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component("StackitKmsAdapter")
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class StackitKmsAdapter extends BaseKmsAdapter {

    private static final Logger log = LoggerFactory.getLogger(StackitKmsAdapter.class);
    private static final String DEFAULT_ENDPOINT = "https://kms.api.eu01.stackit.cloud";

    private final ObjectMapper objectMapper;

    private StackitJwtTokenProvider tokenProvider;
    private StackitKmsApi stackitApi;

    private final Map<String, String> encryptCache = Collections.synchronizedMap(new LinkedHashMap<>(200, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > 200;
        }
    });

    private final Map<String, String> decryptCache = Collections.synchronizedMap(new LinkedHashMap<>(200, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, String> eldest) {
            return size() > 200;
        }
    });

    private final Map<String, CachedKeyVersion> latestKeyVersionCache = new ConcurrentHashMap<>();

    private static class CachedKeyVersion {
        final int version;
        final long timestamp;

        CachedKeyVersion(int version, long timestamp) {
            this.version = version;
            this.timestamp = timestamp;
        }

        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > 60_000; // 60 seconds
        }
    }

    public StackitKmsAdapter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void configure(Map<String, String> parameters) {
        String endpoint = parameters.getOrDefault("endpoint", DEFAULT_ENDPOINT);
        String projectId = parameters.get("projectid");
        String regionId = parameters.get("regionid");
        String keyRingId = parameters.get("keyringid");
        String serviceAccount = parameters.get("serviceaccount");

        if (projectId == null || regionId == null || keyRingId == null || serviceAccount == null) {
            throw new IllegalStateException(
                    "StackitKmsAdapter requires 'projectid', 'regionid', 'keyringid', and 'serviceaccount' parameters. Present: "
                            + parameters.keySet());
        }

        this.tokenProvider = new StackitJwtTokenProvider(serviceAccount);
        this.stackitApi = new StackitKmsApi(endpoint, projectId, regionId, keyRingId, tokenProvider.getAccessToken(),
                objectMapper);
    }

    @Override
    public String[] encryptBatch(List<EncryptOperation> data) {
        try {
            String keyId = data.getFirst().keyName();
            Integer keyVersion = data.getFirst().keyVersion();

            // If no version specified, fetch the latest
            if (keyVersion == null) {
                CachedKeyVersion cachedVersion = latestKeyVersionCache.get(keyId);
                if (cachedVersion != null && !cachedVersion.isExpired()) {
                    keyVersion = cachedVersion.version;
                    log.debug("Using cached latest key version: {}", keyVersion);
                } else {
                    keyVersion = stackitApi.getLatestKeyVersion(keyId);
                    latestKeyVersionCache.put(keyId, new CachedKeyVersion(keyVersion, System.currentTimeMillis()));
                    log.info("Fetched and cached latest key version: {}", keyVersion);
                }
            }

            final Integer finalKeyVersion = keyVersion;

            String[] results = new String[data.size()];
            List<StackitKmsApi.EncryptRequest> requestsToMake = new ArrayList<>();
            List<Integer> indexMap = new ArrayList<>();

            for (int i = 0; i < data.size(); i++) {
                EncryptOperation task = data.get(i);
                String payload = task.toEncryptionPayload(objectMapper);
                String cacheKey = keyId + ":" + finalKeyVersion + ":" + payload;
                
                if (encryptCache.containsKey(cacheKey)) {
                    results[i] = encryptCache.get(cacheKey);
                } else {
                    requestsToMake.add(new StackitKmsApi.EncryptRequest(payload));
                    indexMap.add(i);
                }
            }

            if (!requestsToMake.isEmpty()) {
                tokenProvider.getAccessToken(); // ensure token is valid before API call
                List<StackitKmsApi.EncryptResult> stackitResults = stackitApi.encryptBatch(keyId, finalKeyVersion, requestsToMake);

                for (int i = 0; i < stackitResults.size(); i++) {
                    StackitKmsApi.EncryptResult result = stackitResults.get(i);
                    int originalIndex = indexMap.get(i);
                    EncryptOperation task = data.get(originalIndex);
                    String payload = task.toEncryptionPayload(objectMapper);
                    String encryptedValue = finalKeyVersion + ":" + result.ciphertext();
                    
                    results[originalIndex] = encryptedValue;
                    
                    String cacheKey = keyId + ":" + finalKeyVersion + ":" + payload;
                    encryptCache.put(cacheKey, encryptedValue);
                    
                    String decryptCacheKey = keyId + ":" + finalKeyVersion + ":" + result.ciphertext();
                    decryptCache.put(decryptCacheKey, payload);
                }
            }

            // log metadata per task
            for (EncryptOperation task : data) {
                if (task.metadata() != null) {
                    log.info(
                            "Encrypted data with metadata: {} {}",
                            objectMapper.writeValueAsString(task.metadata()),
                            task.plaintext());
                }
            }

            log.info("Encrypted {} items", data.size());

            return results;
        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    @Override
    public String[] decryptBatch(List<DecryptOperation> data) {
        try {
            String keyId = data.getFirst().keyName();

            String[] payloads = new String[data.size()];
            List<StackitKmsApi.DecryptRequest> requestsToMake = new ArrayList<>();
            List<Integer> indexMap = new ArrayList<>();

            for (int i = 0; i < data.size(); i++) {
                DecryptOperation task = data.get(i);
                String cacheKey = keyId + ":" + task.keyVersion() + ":" + task.ciphertext();
                
                if (decryptCache.containsKey(cacheKey)) {
                    payloads[i] = decryptCache.get(cacheKey);
                } else {
                    requestsToMake.add(new StackitKmsApi.DecryptRequest(task.ciphertext(), task.keyVersion()));
                    indexMap.add(i);
                }
            }

            if (!requestsToMake.isEmpty()) {
                tokenProvider.getAccessToken(); // ensure token is valid before API call
                List<StackitKmsApi.DecryptResult> decodedPayloads = stackitApi.decryptBatch(keyId, requestsToMake);

                for (int i = 0; i < decodedPayloads.size(); i++) {
                    StackitKmsApi.DecryptResult result = decodedPayloads.get(i);
                    int originalIndex = indexMap.get(i);
                    DecryptOperation task = data.get(originalIndex);
                    String decoded = result.plaintext();
                    
                    payloads[originalIndex] = decoded;
                    
                    String cacheKey = keyId + ":" + task.keyVersion() + ":" + task.ciphertext();
                    decryptCache.put(cacheKey, decoded);
                    
                    String encryptCacheKey = keyId + ":" + task.keyVersion() + ":" + decoded;
                    String encryptedValue = task.keyVersion() + ":" + task.ciphertext();
                    encryptCache.put(encryptCacheKey, encryptedValue);
                }
            }

            return Arrays.stream(payloads).map(decoded -> {
                String[] parts = decoded.split(";", 2);

                String metadata = parts.length > 1 ? parts[1] : "{}";
                log.info("Decrypted data with metadata: {}", metadata);

                return parts[0];
            }).toArray(String[]::new);
        } catch (Exception e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

    @Override
    public String[] rewrapBatch(List<RewrapOperation> data) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
