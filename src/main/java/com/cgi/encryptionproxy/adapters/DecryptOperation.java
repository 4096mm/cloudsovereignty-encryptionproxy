package com.cgi.encryptionproxy.adapters;

public record DecryptOperation(String provider, String keyName, Integer keyVersion, String ciphertext) {
    public static DecryptOperation fromString(String provider, String keyName, String ciphertext) {
        // split ciphertext into version and ciphertext parts on :
        String[] parts = ciphertext.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid ciphertext format, expected version:ciphertext");
        }
        Integer keyVersion = Integer.valueOf(parts[0]);
        String actualCiphertext = parts[1];

        return new DecryptOperation(
                provider,
                keyName,
                keyVersion,
                actualCiphertext
        );
    }
}