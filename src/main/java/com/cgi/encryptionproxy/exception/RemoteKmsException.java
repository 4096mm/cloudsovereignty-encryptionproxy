package com.cgi.encryptionproxy.exception;

/**
 * Exception thrown when provided data is not a valid Base64 encoded string
 */
public class RemoteKmsException extends RuntimeException {

    private final String body;
    private final int statusCode;

    public RemoteKmsException(String body, int statusCode) {
        super(String.format("Remote KMS error: %s (Status Code: %d)", body, statusCode));
        this.body = body;
        this.statusCode = statusCode;
    }

    public String getBody() {
        return body;
    }

    public int getStatusCode() {
        return statusCode;
    }
}