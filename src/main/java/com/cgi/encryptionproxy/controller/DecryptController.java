package com.cgi.encryptionproxy.controller;

import com.cgi.encryptionproxy.adapters.DecryptOperation;
import com.cgi.encryptionproxy.adapters.IKmsAdapter;
import com.cgi.encryptionproxy.dto.CiphertextRequest;
import com.cgi.encryptionproxy.dto.PlaintextResponse;
import com.cgi.encryptionproxy.service.ProviderRegistryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
@RequestMapping("/api/v1/decrypt")
public class DecryptController {

    private static final Logger log = LoggerFactory.getLogger(DecryptController.class);

    private final ProviderRegistryService providerRegistryService;

    public DecryptController(ProviderRegistryService providerRegistryService) {
        this.providerRegistryService = providerRegistryService;
    }

    @PostMapping
    public ResponseEntity<List<PlaintextResponse>> decrypt(@RequestBody CiphertextRequest request) {
        List<DecryptOperation> tasks = request.toCryptoTasks(request.getKeyProvider());
        log.info("Received decrypt with {} items", tasks.size());
        IKmsAdapter adapter = providerRegistryService.getProvider(request.getKeyProvider());
        String[] results = adapter.decryptBatch(tasks);

        List<PlaintextResponse> responses = Stream.of(results)
                .map(PlaintextResponse::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(responses);
    }
}
