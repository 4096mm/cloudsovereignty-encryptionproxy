package com.cgi.encryptionproxy.controller;

import com.cgi.encryptionproxy.adapters.EncryptOperation;
import com.cgi.encryptionproxy.adapters.IKmsAdapter;
import com.cgi.encryptionproxy.dto.CiphertextResponse;
import com.cgi.encryptionproxy.dto.PlaintextRequest;
import com.cgi.encryptionproxy.service.ProviderRegistryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/encrypt")
public class EncryptController {

    private final ProviderRegistryService providerRegistryService;

    public EncryptController(ProviderRegistryService providerRegistryService) {
        this.providerRegistryService = providerRegistryService;
    }

    @PostMapping
    public ResponseEntity<List<CiphertextResponse>> encrypt(@RequestBody PlaintextRequest request) {
        IKmsAdapter adapter = providerRegistryService.getProvider(request.getKeyProvider());
        List<EncryptOperation> tasks = request.toCryptoTasks(request.getKeyProvider());
        String[] results = adapter.encryptBatch(tasks);

        List<CiphertextResponse> responses = Stream.of(results)
                .map(CiphertextResponse::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }
}
