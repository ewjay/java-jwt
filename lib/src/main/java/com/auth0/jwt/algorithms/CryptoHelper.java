package com.auth0.jwt.algorithms;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

class CryptoHelper {

    boolean verifySignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        return MessageDigest.isEqual(createSignatureFor(algorithm, secretBytes, contentBytes), signatureBytes);
    }

    byte[] createSignatureFor(String algorithm, byte[] secretBytes, byte[] contentBytes) throws NoSuchAlgorithmException, InvalidKeyException {
        final Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secretBytes, algorithm));
        return mac.doFinal(contentBytes);
    }

    boolean verifySignatureFor(String algorithm, PublicKey publicKey, byte[] contentBytes, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initVerify(publicKey);
        s.update(contentBytes);
        return s.verify(signatureBytes);
    }

    byte[] createSignatureFor(String algorithm, PrivateKey privateKey, byte[] contentBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature s = Signature.getInstance(algorithm);
        s.initSign(privateKey);
        s.update(contentBytes);
        return s.sign();
    }

    byte[] encrypt(String algorithm, PublicKey publicKey, byte[] contentBytes, byte[] iv, byte[] aad) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(contentBytes);
    }

    byte[] decrypt(String algorithm, PrivateKey privateKey, byte[] cipherText, byte[] iv, byte[] aad) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherText);
    }

    byte[] encrypt(String algorithm, Key key, AlgorithmParameterSpec algorithmParameterSpec, byte[] contentBytes, byte[] aad)
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, algorithmParameterSpec);
        if(aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(contentBytes);
    }

    byte[] decrypt(String algorithm, Key key, AlgorithmParameterSpec algorithmParameterSpec, byte[] cipherText, byte[] aad)
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, algorithmParameterSpec);
        if(aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(cipherText);
    }

    byte[] generateAgreementKey(String algorithm, Key privateKey, Key publicKey) throws  NoSuchAlgorithmException, InvalidKeyException{
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    byte[] wrap(String algorithm, Key keywrapKey, byte[] contentBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.WRAP_MODE, keywrapKey);
        return cipher.wrap(new SecretKeySpec(contentBytes, "AES"));
    }

    byte[] unwrap(String algorithm, Key keywrapKey, byte[] cipherText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.UNWRAP_MODE, keywrapKey);
        return cipher.unwrap(cipherText, "AESWrap", Cipher.SECRET_KEY).getEncoded();
    }


}
