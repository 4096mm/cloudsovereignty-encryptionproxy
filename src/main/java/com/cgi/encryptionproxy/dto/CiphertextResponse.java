package com.cgi.encryptionproxy.dto;

/**
 * Response for encryption requests
 */
public class CiphertextResponse {

    private String ciphertext;

    public CiphertextResponse() { }

    public CiphertextResponse(String ciphertext) {
        this.ciphertext = ciphertext;
    }

    public String getCiphertext() { return ciphertext; }
    public void setCiphertext(String ciphertext) { this.ciphertext = ciphertext; }
}
