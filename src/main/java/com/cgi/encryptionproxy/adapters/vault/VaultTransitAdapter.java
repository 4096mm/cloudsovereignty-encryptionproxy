package com.cgi.encryptionproxy.adapters.vault;

import com.cgi.encryptionproxy.adapters.CryptoAdapter;
import com.cgi.encryptionproxy.adapters.DecryptOperation;
import com.cgi.encryptionproxy.adapters.EncryptOperation;
import com.cgi.encryptionproxy.adapters.RewrapOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.List;
import java.util.Map;

@Component("VaultTransitAdapter")
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class VaultTransitAdapter extends CryptoAdapter {

    private static final Logger log = LoggerFactory.getLogger(VaultTransitAdapter.class);

    private String endpoint;
    private String token;

    private final ObjectMapper objectMapper;

    private VaultTransitApi vaultApi;

    public VaultTransitAdapter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void configure(Map<String, String> parameters) {
        this.endpoint = parameters.get("endpoint");
        this.token = parameters.get("token");

        if (endpoint == null || token == null) {
            throw new IllegalStateException(
                    "VaultTransitAdapter requires 'endpoint' and 'token' parameters.");
        }

        this.vaultApi = new VaultTransitApi(endpoint, token, objectMapper);
    }

    /*
     * ============================================================
     * ENCRYPT
     * ============================================================
     */

    @Override
    public String[] encryptBatch(List<EncryptOperation> data) {
        try {
            String keyName = data.getFirst().keyName();

            List<VaultTransitApi.EncryptRequest> requests = data.stream()
                    .map(task -> new VaultTransitApi.EncryptRequest(
                            task.toEncryptionPayload(objectMapper),
                            task.keyVersion()))
                    .toList();

            List<VaultTransitApi.EncryptResult> vaultResults = vaultApi.encryptBatch(keyName, requests);

            List<String> encryptedValues = vaultResults.stream().map(
                    vaultResult -> String.join(":", String.valueOf(vaultResult.keyVersion()), vaultResult.ciphertext()))
                    .toList();

            // log metadata per task
            for (EncryptOperation task : data) {
                if (task.metadata() != null) {
                    log.info(
                            "Encrypted data with metadata: {}",
                            objectMapper.writeValueAsString(task.metadata()));
                }
            }

            return encryptedValues.toArray(String[]::new);
        } catch (Exception e) {
            throw new RuntimeException("Error during encryption", e);
        }
    }

    /*
     * ============================================================
     * DECRYPT
     * ============================================================
     */

    @Override
    public String[] decryptBatch(List<DecryptOperation> data) {
        try {
            String keyName = data.getFirst().keyName();

            List<VaultTransitApi.DecryptRequest> requests = data.stream()
                    .map(task -> new VaultTransitApi.DecryptRequest(task.ciphertext(), task.keyVersion()))
                    .toList();

            List<VaultTransitApi.DecryptResult> decodedPayloads = vaultApi.decryptBatch(keyName, requests);

            return decodedPayloads.stream().map(result -> {
                String decoded = new String(Base64.getDecoder().decode(result.plaintext()));
                String[] parts = decoded.split(";", 2);

                String metadata = parts.length > 1 ? parts[1] : "{}";
                log.info("Decrypted data with metadata: {}", metadata);

                return parts[0];
            }).toArray(String[]::new);
        } catch (Exception e) {
            throw new RuntimeException("Error during decryption", e);
        }
    }

    /*
     * ============================================================
     * REWRAP
     * ============================================================
     */

    @Override
    public String[] rewrapBatch(List<RewrapOperation> data) {
        throw new UnsupportedOperationException("Not implemented");
    }
}
