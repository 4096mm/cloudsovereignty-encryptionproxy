package com.cgi.encryptionproxy.service;

import com.cgi.encryptionproxy.adapters.BaseKmsAdapter;
import com.cgi.encryptionproxy.adapters.IKmsAdapter;
import com.cgi.encryptionproxy.config.ProviderProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ProviderRegistryService {

    private static final Logger log = LoggerFactory.getLogger(ProviderRegistryService.class);

    private final Map<String, BaseKmsAdapter> activeProviders = new ConcurrentHashMap<>();
    private final ProviderProperties properties;
    private final BeanFactory beanFactory;

    public ProviderRegistryService(ProviderProperties properties, BeanFactory beanFactory) {
        this.properties = properties;
        this.beanFactory = beanFactory;

        initializeProviders();
    }

    private void initializeProviders() {
        if (properties.getProviders().isEmpty()) {
            log.error("No providers are configured");
            throw new IllegalStateException("No providers are configured");
        }

        properties.getProviders().forEach((name, config) -> {
            String beanName = config.getType() + "Adapter";

            try {
                BaseKmsAdapter adapter = beanFactory.getBean(beanName, BaseKmsAdapter.class);
                adapter.setName(name);
                adapter.configure(config.getParams());
                activeProviders.put(name, adapter);

                log.info("Successfully registered provider '{}' [Type: {}]", name, config.getType());
            } catch (NoSuchBeanDefinitionException e) {
                log.error("Failed to initialize provider '{}': No bean named '{}' found.", name, beanName);
                throw new IllegalArgumentException("No adapter found for type: " + config.getType(), e);
            } catch (Exception e) {
                log.error("Failed to configure provider '{}': {}", name, e.getMessage());
                throw e;
            }
        });
    }

    public IKmsAdapter getProvider(String name) {
        return Optional.ofNullable(activeProviders.get(name))
                .orElseThrow(() -> new IllegalArgumentException("Provider not found: " + name));
    }
}