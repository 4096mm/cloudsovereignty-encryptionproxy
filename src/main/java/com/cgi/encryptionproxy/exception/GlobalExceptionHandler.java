package com.cgi.encryptionproxy.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidBase64DataException.class)
    public ResponseEntity<ErrorResponse> handleInvalidBase64DataException(InvalidBase64DataException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                "Invalid Base64 Data",
                ex.getMessage(),
                HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(RemoteKmsException.class)
    public ResponseEntity<ErrorResponse> handleRemoteKmsException(RemoteKmsException ex) {
        ErrorResponse errorResponse = new ErrorResponse(
                "Remote KMS Error",
                ex.getBody(),
                ex.getStatusCode());
        return ResponseEntity.status(ex.getStatusCode()).body(errorResponse);
    }
}
