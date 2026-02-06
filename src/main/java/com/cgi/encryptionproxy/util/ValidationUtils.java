package com.cgi.encryptionproxy.util;

import com.cgi.encryptionproxy.exception.InvalidBase64DataException;

public class ValidationUtils {

    private ValidationUtils() {
        // Utility class, no instantiation
    }

    public static boolean isBase64Encoded(String data) {
        return data.matches("^[A-Za-z0-9+/=]+$");
    }

    /**
     * Checks if the provided data is a valid Base64 encoded string, and throws an exception if it is not
     * @param data the string to validate
     * @throws InvalidBase64DataException if data is not valid Base64 encoded string
     */
    public static void requireBase64Encoded(String data) {
        if (!isBase64Encoded(data)) {
            throw new InvalidBase64DataException(data);
        }
    }
}