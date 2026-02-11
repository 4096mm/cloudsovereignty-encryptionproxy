package com.cgi.encryptionproxy.controller;

import com.cgi.encryptionproxy.adapters.DecryptOperation;
import com.cgi.encryptionproxy.adapters.EncryptOperation;
import com.cgi.encryptionproxy.adapters.IKmsAdapter;
import com.cgi.encryptionproxy.dto.CiphertextRequest;
import com.cgi.encryptionproxy.dto.CiphertextResponse;
import com.cgi.encryptionproxy.dto.PlaintextRequest;
import com.cgi.encryptionproxy.dto.PlaintextResponse;
import com.cgi.encryptionproxy.service.ProviderRegistryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class EncryptionController {

    private final ProviderRegistryService providerRegistryService;

    public EncryptionController(ProviderRegistryService providerRegistryService) {
        this.providerRegistryService = providerRegistryService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<List<CiphertextResponse>> encrypt(@RequestBody PlaintextRequest request) {
        IKmsAdapter adapter = providerRegistryService.getProvider(request.getKeyProvider());
        List<EncryptOperation> tasks = request.toCryptoTasks(request.getKeyProvider());
        String[] results = adapter.encryptBatch(tasks);

        List<CiphertextResponse> responses = List.of(results).stream()
                .map(CiphertextResponse::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<List<PlaintextResponse>> decrypt(@RequestBody CiphertextRequest request) {
        List<DecryptOperation> tasks = request.toCryptoTasks(request.getKeyProvider());
        IKmsAdapter adapter = providerRegistryService.getProvider(request.getKeyProvider());
        String[] results = adapter.decryptBatch(tasks);

        List<PlaintextResponse> responses = List.of(results).stream()
                .map(PlaintextResponse::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }
}
