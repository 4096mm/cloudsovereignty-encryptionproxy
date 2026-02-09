package com.cgi.encryptionproxy.adapters;

import java.util.List;
import java.util.Map;

public interface ICryptoAdapter {
    /**
     * Configures the crypto adapter with implementation-specific parameters.
     *
     * @param parameters Map of configuration parameters where:
     *        - Keys are parameter names (e.g., "endpoint", "token")
     *        - Values are parameter values as strings
     */
    void configure(Map<String, String> parameters);

    /**
     * Encrypts a batch of cryptographic operations.
     *
     * @param data an array of CryptoOperation objects to be encrypted
     * @return the result of the encryption operation as a String
     */
    String[] encryptBatch(List<CryptoTask> data);

    /**
     * Decrypts a batch of cryptographic operations.
     *
     * @param data an array of CryptoOperation objects to be decrypted
     * @return the result of the decryption operation as a String
     */
    String[] decryptBatch(List<CryptoTask> data);

    /**
     * Rewraps a batch of cryptographic operations (used for key wrapping/unwrap).
     *
     * @param data an array of CryptoOperation objects to be rewrapped
     * @return the result of the rewrapping operation as a String
     */
    String[] rewrapBatch(List<CryptoTask> data);
}