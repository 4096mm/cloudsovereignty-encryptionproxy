package com.cgi.encryptionproxy.util;

import com.cgi.encryptionproxy.exception.InvalidBase64DataException;

import java.util.Base64;

public class ValidationUtils {

    private ValidationUtils() {
    }

    public static boolean isBase64Encoded(String data) {
        if (data == null || data.length() % 4 != 0) {
            return false;
        }

        try {
            Base64.getDecoder().decode(data);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks if the provided data is a valid Base64 encoded string, and throws an exception if it is not
     *
     * @param data the string to validate
     * @throws InvalidBase64DataException if data is not valid Base64 encoded string
     */
    public static void requireBase64Encoded(String data) {
        if (!isBase64Encoded(data)) {
            throw new InvalidBase64DataException(data);
        }
    }
}