package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AESGCMAlgorithm extends JWEContentEncryptionAlgorithm {
    private final CryptoHelper crypto;
    private int keySize;
    private CipherParams cipherParams;

    AESGCMAlgorithm(CryptoHelper crypto, String id, String algorithm, CipherParams cipherParams) throws IllegalArgumentException {
        super(id, algorithm);
        this.crypto = crypto;
        this.cipherParams = cipherParams;
        keySize = Integer.parseInt(id.substring(1, 4));
        if (cipherParams == null) {
            throw new IllegalArgumentException("The cipher param cannot be null");
        }
        if(cipherParams.getEncKey().length * 8 != keySize) {
            String error = String.format("The key size is invalid for the algorithm %s. Expected size : %d Actual : %d", id, keySize, cipherParams.getEncKey().length * 8);
            throw new IllegalArgumentException(error);
        }
        if(cipherParams.getIv().length * 8 != 96) {
            String error = String.format("The IV size is invalid for the algorithm %s. Expected size : 96 Actual : %d", id, cipherParams.getIv().length * 8);
            throw new IllegalArgumentException(error);
        }


    }

    AESGCMAlgorithm(String id, String algorithm, CipherParams cipherParams) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, cipherParams);
    }

    public CipherParams getCipherParams() {
        return cipherParams;
    }

    @Override
    public AuthenticatedCipherText encrypt(byte[] contentBytes, byte[] aad) throws EncryptionException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(cipherParams.getEncKey(), "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, cipherParams.getIv());
            byte[] cipherTextWithTag = crypto.encrypt(getDescription(), secretKeySpec, gcmParameterSpec, contentBytes, aad);
            // break cipherTextWithTag into cipherText & tag
            byte[] cipherText = Arrays.copyOfRange(cipherTextWithTag, 0, cipherTextWithTag.length - 16);
            byte[] authTag = Arrays.copyOfRange(cipherTextWithTag, cipherTextWithTag.length - 16, cipherTextWithTag.length);
            return new AuthenticatedCipherText(cipherText, authTag);
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException(this, e);
        }
    }

    @Override
    public byte[] decrypt(byte[] cipherText, byte[] authTag, byte[] aad) throws DecryptionException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(cipherParams.getEncKey(), "AES");
            ByteBuffer byteBuffer = ByteBuffer.allocate(cipherText.length + authTag.length);
            byteBuffer.put(cipherText).put(authTag);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, cipherParams.getIv());
            return crypto.decrypt(getDescription(), secretKeySpec, gcmParameterSpec, byteBuffer.array(), aad);
        } catch(Exception e) {
            throw new DecryptionException(this, e);
        }
    }
}
