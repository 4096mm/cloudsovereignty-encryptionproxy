package com.cgi.encryptionproxy.exception;

/**
 * Exception thrown when provided data is not a valid Base64 encoded string
 */
public class InvalidBase64DataException extends RuntimeException {

    private final String invalidValueString;

    public InvalidBase64DataException(String invalidValue) {
        super(String.format("The provided string \"%s\" is not a valid Base64 encoded string.", invalidValue));
        this.invalidValueString = invalidValue;
    }

    public InvalidBase64DataException(String invalidValue, Throwable cause) {
        super(String.format("The provided string \"%s\" is not a valid Base64 encoded string.", invalidValue), cause);
        this.invalidValueString = invalidValue;
    }

    public String getInvalidValueString() {
        return invalidValueString;
    }
}