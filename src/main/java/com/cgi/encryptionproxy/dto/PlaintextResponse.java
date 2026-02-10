package com.cgi.encryptionproxy.dto;

/**
 * Response for decryption requests
 */
public class PlaintextResponse {

    private String plaintext;

    public PlaintextResponse() { }

    public PlaintextResponse(String plaintext) {
        this.plaintext = plaintext;
    }

    public String getPlaintext() { return plaintext; }
    public void setPlaintext(String plaintext) { this.plaintext = plaintext; }
}
