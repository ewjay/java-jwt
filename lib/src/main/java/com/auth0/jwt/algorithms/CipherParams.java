package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.KeyAgreementException;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

public class CipherParams {
    private byte[] encKey;
    private byte[] macKey;
    private byte[] iv;

    public CipherParams(byte[] encKey, byte[] macKey, byte[] iv) {
        this.encKey = encKey;
        this.macKey = macKey;
        this.iv = iv;
    }

    public CipherParams(byte[] encKey, byte[] iv) {
        this(encKey, new byte[0], iv);
    }


    public static CipherParams getInstance(String algorithm) {
        return getInstance(algorithm, null);
    }

    public static CipherParams getKeyAgreementInstance(String encAlgorithm, Algorithm algorithm) throws KeyAgreementException {
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
            }  else if("ECDH-ES+A128KW".equals(encAlgorithm)) {
                requiredLen = 16;
                ivLength = 0;
                encKeyLength = 16;
            } else if("ECDH-ES+A192KW".equals(encAlgorithm)) {
                requiredLen = 24;
                ivLength = 0;
                encKeyLength = 24;
            } else if("ECDH-ES+A256KW".equals(encAlgorithm)) {
                requiredLen = 32;
                ivLength = 0;
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

    public byte[] getEncKey() {
        return encKey;
    }

    public void setEncKey(byte[] encKey) {
        this.encKey = encKey;
    }

    public byte[] getMacKey() {
        return macKey;
    }

    public byte[] getMacEncKey() {
        ByteBuffer byteBuffer = ByteBuffer.allocate(macKey.length + encKey.length);
        byteBuffer.put(macKey);
        byteBuffer.put(encKey);
        return byteBuffer.array();
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }
}
