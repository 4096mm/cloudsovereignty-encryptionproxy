package com.cgi.encryptionproxy.util;

import com.cgi.encryptionproxy.adapters.ICryptoAdapter;

import tools.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ProviderRegistry {

    private final Map<String, ICryptoAdapter> keyProviders = new ConcurrentHashMap<>();
    private final Map<String, Map<String, String>> providerParameters = new ConcurrentHashMap<>();

    public ProviderRegistry(@Value("${KEY_PROVIDERS_CONFIG:#{null}}") String providerConfigJson) throws Exception {
        if (providerConfigJson == null || providerConfigJson.isEmpty()) {
            throw new IllegalStateException("Provider configuration JSON must be provided.");
        }

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Map<String, String>> providerConfigs = objectMapper.readValue(providerConfigJson, Map.class);

        for (Map.Entry<String, Map<String, String>> entry : providerConfigs.entrySet()) {
            String providerName = entry.getKey();
            Map<String, String> config = entry.getValue();

            String providerType = config.get("type");
            if (providerType == null) {
                throw new IllegalArgumentException("Provider type must be specified for provider: " + providerName);
            }

            // Override or set parameters with environment variables
            config.forEach((key, value) -> {
                String envVar = System.getenv("PROVIDERS_" + providerName.toUpperCase() + "_" + key.toUpperCase());
                if (envVar != null) {
                    config.put(key, envVar);
                }
            });

            // Add additional parameters from environment variables
            System.getenv().forEach((envKey, envValue) -> {
                String prefix = "PROVIDERS_" + providerName.toUpperCase() + "_";
                if (envKey.startsWith(prefix)) {
                    String paramKey = envKey.substring(prefix.length()).toLowerCase();
                    config.putIfAbsent(paramKey, envValue);
                }
            });

            // Store parameters for later use
            providerParameters.put(providerName, config);

            ICryptoAdapter provider = createProviderInstance(providerType, config);
            keyProviders.put(providerName, provider);
        }
    }

    private ICryptoAdapter createProviderInstance(String providerType, Map<String, String> config) {
        try {
            Class<?> clazz = Class.forName("com.cgi.encryptionproxy.adapters." + providerType + "Adapter");
            ICryptoAdapter adapter = (ICryptoAdapter) clazz.getDeclaredConstructor().newInstance();

            // Pass configuration parameters to the adapter if supported
            if (adapter instanceof ConfigurableAdapter) {
                ((ConfigurableAdapter) adapter).configure(config);
            }

            return adapter;
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to create provider instance for type: " + providerType, e);
        }
    }

    public ICryptoAdapter getProvider(String providerName) {
        ICryptoAdapter provider = keyProviders.get(providerName);
        if (provider == null) {
            throw new IllegalArgumentException("Unknown key provider: " + providerName);
        }
        return provider;
    }

    public Map<String, String> getProviderParameters(String providerName) {
        return providerParameters.get(providerName);
    }

    public interface ConfigurableAdapter {
        void configure(Map<String, String> parameters);
    }
}