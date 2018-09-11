package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class AESHSAlgorithm extends Algorithm {

    private final CryptoHelper crypto;
    private int keySize;
    private CipherParams cipherParams;
    private Algorithm hmacAlg;
    private int hmacByteLength;

    //Visible for testing

    AESHSAlgorithm(CryptoHelper crypto, String id, String algorithm, CipherParams cipherParams) throws IllegalArgumentException {
        super(id, algorithm);
        this.crypto = crypto;
        this.cipherParams = cipherParams;
        keySize = Integer.parseInt(id.substring(1, 4));
        String hmacAlgId = id.substring(8);
        if("HS256".equals(hmacAlgId)) {
            hmacAlg = Algorithm.HMAC256(cipherParams.getMacKey());
        } else if("HS384".equals(hmacAlgId)) {
            hmacAlg = Algorithm.HMAC384(cipherParams.getMacKey());
        } else if("HS512".equals(hmacAlgId)) {
            hmacAlg = Algorithm.HMAC512(cipherParams.getMacKey());
        }

        hmacByteLength = Integer.parseInt(id.substring(10)) / 16 /* half the bit length converted into byte (2*8) */;

        if (cipherParams == null) {
            throw new IllegalArgumentException("The cipher param cannot be null");
        }
        if(cipherParams.getEncKey().length * 8 != keySize) {
            String error = String.format("The key size is invalid for the algorithm %s. Expected size : %d Actual : %d", id, keySize, cipherParams.getEncKey().length * 8);
            throw new IllegalArgumentException(error);
        }
        if(cipherParams.getIv().length * 8 != 128) {
            String error = String.format("The IV size is invalid for the algorithm %s. Expected size : 128 Actual : %d", id, cipherParams.getIv().length * 8);
            throw new IllegalArgumentException(error);
        }

    }

    AESHSAlgorithm(String id, String algorithm, CipherParams cipherParams) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, cipherParams);
    }

    public CipherParams getCipherParams() {
        return cipherParams;
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }

    @Override
    public void verify(DecodedJWT jwt) throws SignatureVerificationException {

    }

    @Override
    public AuthenticatedCipherText encrypt(byte[] contentBytes, byte[] aad) throws EncryptionException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(cipherParams.getEncKey(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(cipherParams.getIv());
            byte[] cipherText = crypto.encrypt(getDescription(), secretKeySpec, ivParameterSpec, contentBytes, null);
            byte[] authTag = null;

            if(aad != null && hmacAlg != null) {
                ByteBuffer byteBuffer = ByteBuffer.allocate(aad.length + cipherParams.getIv().length + cipherText.length + (Long.SIZE / Byte.SIZE));
                byteBuffer.put(aad);
                byteBuffer.put(cipherParams.getIv());
                byteBuffer.put(cipherText);
                byte[] AL = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(aad.length * 8).array();
                byteBuffer.put(AL);
                authTag = Arrays.copyOfRange(hmacAlg.sign(byteBuffer.array()), 0, hmacByteLength);
            }
            return new AuthenticatedCipherText(cipherText, authTag);
        } catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new EncryptionException(this, e);
        }

    }

    @Override
    public byte[] decrypt(byte[] cipherText, byte[] authTag, byte[] aad) throws DecryptionException {
        try {

            if(aad != null && hmacAlg != null) {
                System.out.printf("cek : %s\ncik : %s\niv : %s\nTag : %s\n",
                    Hex.encodeHexString(cipherParams.getEncKey()),
                    Hex.encodeHexString(cipherParams.getMacKey()),
                    Hex.encodeHexString(cipherParams.getIv()),
                    Hex.encodeHexString(authTag)
                );
                ByteBuffer byteBuffer = ByteBuffer.allocate(aad.length + cipherParams.getIv().length + cipherText.length + (Long.SIZE / Byte.SIZE));
                byteBuffer.put(aad);
                byteBuffer.put(cipherParams.getIv());
                byteBuffer.put(cipherText);
                byte[] AL = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(aad.length * 8).array();
                byteBuffer.put(AL);
                System.out.printf("hmac input : %s\n",
                    Hex.encodeHexString(byteBuffer.array())
                );

                byte[] calculatedAuthTag = Arrays.copyOfRange(hmacAlg.sign(byteBuffer.array()), 0, hmacByteLength);
                if(!Arrays.equals(authTag, calculatedAuthTag)) {
                    throw new Exception("Authentication tag does not match.");
                }
            }
            SecretKeySpec secretKeySpec = new SecretKeySpec(cipherParams.getEncKey(), "AES");
            IvParameterSpec ivParameterSpec = new IvParameterSpec(cipherParams.getIv());
            return crypto.decrypt(getDescription(), secretKeySpec, ivParameterSpec, cipherText, null);
        } catch(Exception e) {
            throw new DecryptionException(this, e);
        }
    }

}
