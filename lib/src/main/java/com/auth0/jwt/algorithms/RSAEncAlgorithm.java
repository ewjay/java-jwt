package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;

class RSAEncAlgorithm extends JWEKeyEncryptionAlgorithm {

    private final RSAKeyProvider keyProvider;
    private final CryptoHelper crypto;

    //Visible for testing
    RSAEncAlgorithm(CryptoHelper crypto, String id, String algorithm, RSAKeyProvider keyProvider) throws IllegalArgumentException {
        super(id, algorithm);
        if (keyProvider == null) {
            throw new IllegalArgumentException("The Key Provider cannot be null.");
        }
        this.keyProvider = keyProvider;
        this.crypto = crypto;
    }

    RSAEncAlgorithm(String id, String algorithm, RSAKeyProvider keyProvider) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, keyProvider);
    }

    @Override
    public String getSigningKeyId() {
        return keyProvider.getPrivateKeyId();
    }

    //Visible for testing
    static RSAKeyProvider providerForKeys(final RSAPublicKey publicKey, final RSAPrivateKey privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }
        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String keyId) {
                return publicKey;
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return privateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }


    @Override
    public byte[] encrypt(byte[] contentBytes) throws EncryptionException{
        try {
            if("RSA-OAEP-256".equals(getName())) {
                OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                return crypto.encrypt(getDescription(), keyProvider.getPublicKeyById(""), oaepParams, contentBytes, null);
            } else {
                return crypto.encrypt(getDescription(), keyProvider.getPublicKeyById(""),contentBytes , null, null);
            }
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException(this, e);
        }
    }


    @Override
    public byte[] decrypt(byte[] cipherText) throws DecryptionException{
        try {
            if("RSA-OAEP-256".equals(getName())) {
                OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
                return crypto.decrypt(getDescription(), keyProvider.getPrivateKey(), oaepParams, cipherText, null);
            } else {
                return crypto.decrypt(getDescription(), keyProvider.getPrivateKey(), cipherText, null, null);
            }
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new DecryptionException(this, e);
        }
    }
}
