package com.auth0.msg;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.JWEKeyEncryptionAlgorithm;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class RSACryptoTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testRSA15() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte bytes[] = new byte[245];
        secureRandom.nextBytes(bytes);

        System.out.println(Hex.encodeHexString(bytes));

        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        for(int i = 0; i < 3; i++) {
            JWEKeyEncryptionAlgorithm algorithm =  Algorithm.RSA1_5(rsaPublicKey, rsaPrivateKey);
            byte[] cipherText = algorithm.encrypt(bytes);
            System.out.println(Hex.encodeHexString(cipherText));

            byte[] plainText = algorithm.decrypt(cipherText);
            System.out.println(Hex.encodeHexString(plainText));
            Assert.assertTrue(Arrays.equals(bytes, plainText));
        }
    }


    @Test
    public void testRSAOAEP() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte bytes[] = new byte[214];
        secureRandom.nextBytes(bytes);

        System.out.println(Hex.encodeHexString(bytes));

        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        for(int i = 0; i < 3; i++) {
            JWEKeyEncryptionAlgorithm algorithm =  Algorithm.RSAOAEP(rsaPublicKey, rsaPrivateKey);
            byte[] cipherText = algorithm.encrypt(bytes);
            System.out.println(Hex.encodeHexString(cipherText));

            byte[] plainText = algorithm.decrypt(cipherText);
            System.out.println(Hex.encodeHexString(plainText));
            Assert.assertTrue(Arrays.equals(bytes, plainText));
        }
    }

    @Test
    public void testRSAOAEP256() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte bytes[] = new byte[190];
        secureRandom.nextBytes(bytes);

        System.out.println(Hex.encodeHexString(bytes));

        KeyPair keyPair = RSAKey.generateRSAKeyPair(2048);
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

        for(int i = 0; i < 3; i++) {
            JWEKeyEncryptionAlgorithm algorithm =  Algorithm.RSAOAEP256(rsaPublicKey, rsaPrivateKey);
            byte[] cipherText = algorithm.encrypt(bytes);
            System.out.println(Hex.encodeHexString(cipherText));

            byte[] plainText = algorithm.decrypt(cipherText);
            System.out.println(Hex.encodeHexString(plainText));
            Assert.assertTrue(Arrays.equals(bytes, plainText));
        }
    }

    @Test
    public void testKeyGenerator() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();

        byte[] key = secretKey.getEncoded();
        System.out.println(Hex.encodeHexString(key));
        for(int i = 0; i < key.length; i++) {
            System.out.printf("%02X ", key[i]);
        }

        System.out.println();

        byte[] intBytes = BigInteger.valueOf(2048).toByteArray();
        System.out.println(Hex.encodeHexString(intBytes));
        for(int i = 0; i < intBytes.length; i++) {
            System.out.printf("%02X ", intBytes[i]);
        }
    }
}
