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

import java.util.List;
import java.util.Map;

@Component("StackitKmsAdapter")
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class StackitKmsAdapter extends BaseKmsAdapter {

    private static final Logger log = LoggerFactory.getLogger(StackitKmsAdapter.class);
    private static final String DEFAULT_ENDPOINT = "https://kms.api.eu01.stackit.cloud";

    private final ObjectMapper objectMapper;

    private StackitJwtTokenProvider tokenProvider;
    private StackitKmsApi stackitApi;

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
                keyVersion = stackitApi.getLatestKeyVersion(keyId);
                log.info("Using latest key version: {}", keyVersion);
            }

            List<StackitKmsApi.EncryptRequest> requests = data.stream()
                    .map(task -> new StackitKmsApi.EncryptRequest(
                            task.toEncryptionPayload(objectMapper)))
                    .toList();

            tokenProvider.getAccessToken(); // ensure token is valid before API call
            List<StackitKmsApi.EncryptResult> stackitResults = stackitApi.encryptBatch(keyId, keyVersion, requests);

            final Integer finalKeyVersion = keyVersion;
            List<String> encryptedValues = stackitResults.stream()
                    .map(result -> String.join(":", String.valueOf(finalKeyVersion), result.ciphertext()))
                    .toList();

            // log metadata per task
            for (EncryptOperation task : data) {
                if (task.metadata() != null) {
                    log.info(
                            "Encrypted data with metadata: {} {}",
                            objectMapper.writeValueAsString(task.metadata()),
                            task.plaintext());
                }
            }

            log.info("Encrypted {} items", encryptedValues.size());

            return encryptedValues.toArray(String[]::new);
        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    @Override
    public String[] decryptBatch(List<DecryptOperation> data) {
        try {
            String keyId = data.getFirst().keyName();

            List<StackitKmsApi.DecryptRequest> requests = data.stream()
                    .map(task -> new StackitKmsApi.DecryptRequest(task.ciphertext(), task.keyVersion()))
                    .toList();

            tokenProvider.getAccessToken(); // ensure token is valid before API call
            List<StackitKmsApi.DecryptResult> decodedPayloads = stackitApi.decryptBatch(keyId, requests);

            return decodedPayloads.stream().map(result -> {
                String decoded = result.plaintext();
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
