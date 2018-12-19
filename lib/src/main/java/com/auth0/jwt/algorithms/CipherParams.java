package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.KeyAgreementException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class for holding the ENC_KEY (content encryption key), MAC_KEY (authentication tag key) and IV
 * for JWE encryption https://tools.ietf.org/html/rfc7518#section-5
 *
 */
public class CipherParams {
    private byte[] encKey;
    private byte[] macKey;
    private byte[] iv;


    /**
     * Creates a instance using the specified keys and IV. It is assumed that the application
     * passes in the correct length for each of the keys
     * @param encKey ENC_KEY bytes
     * @param macKey MAC_KEY bytes
     * @param iv Initialiation vector
     */
    public CipherParams(byte[] encKey, byte[] macKey, byte[] iv) {
        setEncKey(encKey);
        setMacKey(macKey);
        setIv(iv);
    }

    /**
     * Creates an instance using only ENC_KEY and initialion vector. It is used by GCM algorithms
     * @param encKey
     * @param iv
     */
    public CipherParams(byte[] encKey, byte[] iv) {
        this(encKey, null, iv);
    }


    /**
     * Creates an instance for the specified encryption algorithm as specified by
     * https://tools.ietf.org/html/rfc7518#section-5
     * @param algorithm algorithm string
     * @return new instance suitable for the specified algorithm
     */
    public static CipherParams getInstance(String algorithm) {
        return getInstance(algorithm, null);
    }

    /**
     * Creates an instance for the specified content encryption algorithm that uses key agreement
     * for key encryption
     * @param encAlgorithm content encryption algorithm
     * @param algorithm JWEKeyAgreementAlgorithm for the key agreement
     * @return new instance
     * @throws KeyAgreementException
     */
    public static CipherParams getKeyAgreementInstance(String encAlgorithm, JWEKeyAgreementAlgorithm algorithm) throws KeyAgreementException {
        int ivLength = 16;
        int encKeyLength = 0;
        int macKeyLength = 0;

        int requiredLen = 0;
        SecureRandom secureRandom = new SecureRandom();
        if(encAlgorithm != null && encAlgorithm.length() > 0) {
            if(("A128CBC-HS256").equals(encAlgorithm)) {
                requiredLen = 32;
                encKeyLength = 16;
                macKeyLength = 16;
            } else if("A192CBC-HS384".equals(encAlgorithm)) {
                requiredLen = 48;
                encKeyLength = 24;
                macKeyLength = 24;
            } else if("A256CBC-HS512".equals(encAlgorithm)) {
                requiredLen = 64;
                encKeyLength = 32;
                macKeyLength = 32;
            } else if("A128GCM".equals(encAlgorithm)) {
                requiredLen = 16;
                ivLength = 12;
                encKeyLength = 16;
            } else if("A192GCM".equals(encAlgorithm)) {
                requiredLen = 24;
                ivLength = 12;
                encKeyLength = 24;
            } else if("A256GCM".equals(encAlgorithm)) {
                requiredLen = 32;
                ivLength = 12;
                encKeyLength = 32;
            }
        }

        byte[] encKey = new byte[0];
        byte[] macKey = new byte[0];
        byte[] iv = new byte[ivLength];
        if(ivLength >  0) {
            secureRandom.nextBytes(iv);
        }
        byte[] CMK = algorithm.generateDerivedKey();
        if(CMK.length != requiredLen) {
            throw new KeyAgreementException(algorithm, "Invalid derived key length for enc alg " + encAlgorithm);
        }
        int curPos = 0;
        if(macKeyLength > 0) {
            macKey = Arrays.copyOfRange(CMK, curPos, macKeyLength);
            curPos += macKeyLength;
        }
        if(encKeyLength > 0) {
            encKey = Arrays.copyOfRange(CMK, curPos, curPos + encKeyLength);
        }
        return new CipherParams(encKey, macKey, iv);
    }

    /**
     * Creates an instance for the specified algorithm using the specified SecureRandom generator
     * @param algorithm algorithm string
     * @param secureRandom SecureRandom generator instance to use for generating random values
     * @return new instance
     */
    public static CipherParams getInstance(String algorithm, SecureRandom secureRandom) {
        int ivLength = 16;
        int encKeyLength = 0;
        int macKeyLength = 0;
        if(secureRandom == null) {
            secureRandom = new SecureRandom();
        }

        if(algorithm != null && algorithm.length() > 0) {
            if(("A128CBC-HS256").equals(algorithm)) {
                encKeyLength = 16;
                macKeyLength = 16;
            } else if("A192CBC-HS384".equals(algorithm)) {
                encKeyLength = 24;
                macKeyLength = 24;
            } else if("A256CBC-HS512".equals(algorithm)) {
                encKeyLength = 32;
                macKeyLength = 32;
            } else if("A128GCM".equals(algorithm)) {
                ivLength = 12;
                encKeyLength = 16;
            } else if("A192GCM".equals(algorithm)) {
                ivLength = 12;
                encKeyLength = 24;
            } else if("A256GCM".equals(algorithm)) {
                ivLength = 12;
                encKeyLength = 32;
            }
        }

        byte[] encKey = new byte[encKeyLength];
        byte[] macKey = new byte[macKeyLength];
        byte[] iv = new byte[ivLength];
        if(encKeyLength > 0) {
            secureRandom.nextBytes(encKey);
        }
        if(macKeyLength > 0) {
            secureRandom.nextBytes(macKey);
        }
        if(ivLength >  0) {
            secureRandom.nextBytes(iv);
        }
        return new CipherParams(encKey, macKey, iv);
    }

    /**
     * Gets the ENC_KEY used for content encryption
     * @return ENC_KEY bytes
     */
    public byte[] getEncKey() {
        return encKey;
    }

    /**
     * Sets the ENC_KEY used for content encryption
     * @param encKey ENC_KEY bytes
     */
    public void setEncKey(byte[] encKey) {
        this.encKey = encKey == null ? new  byte[0] : encKey;
    }

    /**
     * Gets the MAC_KEY used for MAC validation
     * @return MAC_KEY bytes
     */
    public byte[] getMacKey() {
        return macKey;
    }

    /**
     * Gets the concatenation of the MAC_KEY and ENC_KEY bytes
     * @return concatenated bytes of both keys
     */
    public byte[] getMacEncKey() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(macKey.length + encKey.length);
        byteBuffer.put(macKey);
        byteBuffer.put(encKey);
        return byteBuffer.array();
    }

    /**
     * Sets the MAC_KEY bytes
     * @param macKey
     */
    public void setMacKey(byte[] macKey) {
        this.macKey = macKey == null ? new byte[0] : macKey;
    }

    /**
     * Gets the initialization vector bytes
     * @return IV bytes
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * Sets the initialization vector bytes
     * @param iv IV bytes
     */
    public void setIv(byte[] iv) {
        this.iv = iv == null ? new byte[0] : iv;
    }
}
