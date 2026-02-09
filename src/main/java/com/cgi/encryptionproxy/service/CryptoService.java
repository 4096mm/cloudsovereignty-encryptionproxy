package com.cgi.encryptionproxy.service;

import com.cgi.encryptionproxy.adapters.CryptoTask;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;

@Service
public class CryptoService {

    private final ObjectMapper objectMapper;

    public CryptoService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String getCryptoTaskPayload(CryptoTask cryptoTask) {
        String metadata = "";
        if(cryptoTask.getMetadata() != null) {
            try {
                metadata = objectMapper.writeValueAsString(cryptoTask.getMetadata());
            } catch (Exception e) {
                throw new RuntimeException("Failed to serialize metadata", e);
            }
        }

        String payload = cryptoTask.getDataBase64() + ";" + metadata;
        return Base64.getEncoder().encodeToString(payload.getBytes());
    }
}
