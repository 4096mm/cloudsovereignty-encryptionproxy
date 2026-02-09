package com.cgi.encryptionproxy.adapters;

public interface CryptoTask {
    String getKeyName();
    Integer getKeyVersion();
    String getDataBase64();
    Object getMetadata();
}
