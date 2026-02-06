package com.cgi.encryptionproxy.adapters;

public interface ICryptoAdapter {
    
    public String[] encryptBatch(CryptoOperation[] data);

    public String decryptBatch(CryptoOperation[] data);

    public String rewrapBatch(CryptoOperation[] data);

}
