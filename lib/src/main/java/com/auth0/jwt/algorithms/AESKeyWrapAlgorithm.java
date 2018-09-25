package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.crypto.spec.SecretKeySpec;

public class AESKeyWrapAlgorithm extends Algorithm {
    private final CryptoHelper crypto;
    private byte[] keywrapKey;

    //Visible for testing

    AESKeyWrapAlgorithm(CryptoHelper crypto, String id, String algorithm, byte[] keywrapKey) throws IllegalArgumentException {
        super(id, algorithm);
        if(keywrapKey == null || keywrapKey.length == 0) {
            throw new IllegalArgumentException("Keywrap encryption key cannot be empty or null.");
        }
        int requiredLen = 0;
        if("A128KW".equals(id)) {
            requiredLen = 16;
        } else if("A192KW".equals(id)) {
            requiredLen = 24;
        } else if("A256KW".equals(id)) {
            requiredLen = 32;
        } else {
            throw new IllegalArgumentException("Unknown KeyWrap algorithm " + id);
        }
        if(requiredLen != keywrapKey.length) {
            String error = String.format("Invald keywarp key length for algorithm %s. Expected %d Actual %d", id, requiredLen, keywrapKey.length);
            throw new IllegalArgumentException(error);
        }
        this.crypto = crypto;
        this.keywrapKey = keywrapKey;
    }

    AESKeyWrapAlgorithm(String id, String algorithm, byte[] keywrapKey) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, keywrapKey);
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }

    @Override
    public void verify(DecodedJWT jwt) throws SignatureVerificationException {

    }

    @Override
    public byte[] wrap(byte[] contentBytes) throws EncryptionException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(keywrapKey, "AES");
            return crypto.wrap(getDescription(), secretKeySpec, contentBytes);

        } catch (Exception e) {
            throw new EncryptionException(this, e);
        }
    }

    @Override
    public byte[] unwrap(byte[] cipherText) throws DecryptionException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(keywrapKey, "AES");
            return crypto.unwrap(getDescription(), secretKeySpec, cipherText);

        } catch (Exception e) {
            throw new DecryptionException(this, e);
        }
    }
}
