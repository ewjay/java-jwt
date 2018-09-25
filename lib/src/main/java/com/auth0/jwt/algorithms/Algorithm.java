package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;

import java.io.UnsupportedEncodingException;
import java.security.interfaces.*;
import java.util.Collections;
import java.util.Map;

/**
 * The Algorithm class represents an algorithm to be used in the Signing or Verification process of a Token.
 */
@SuppressWarnings("WeakerAccess")
public abstract class Algorithm {

    private final String name;
    private final String description;

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid RSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm RSA256(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS256", "SHA256withRSA", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid RSA256 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA256(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA256(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using SHA256withRSA. Tokens specify this as "RS256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA256 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     * @deprecated use {@link #RSA256(RSAPublicKey, RSAPrivateKey)} or {@link #RSA256(RSAKeyProvider)}
     */
    @Deprecated
    public static Algorithm RSA256(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return RSA256(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid RSA384 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm RSA384(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS384", "SHA384withRSA", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid RSA384 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA384(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA384(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using SHA384withRSA. Tokens specify this as "RS384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #RSA384(RSAPublicKey, RSAPrivateKey)} or {@link #RSA384(RSAKeyProvider)}
     */
    @Deprecated
    public static Algorithm RSA384(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return RSA384(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid RSA512 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm RSA512(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RS512", "SHA512withRSA", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid RSA512 Algorithm.
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA512(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA512(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using SHA512withRSA. Tokens specify this as "RS512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid RSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #RSA512(RSAPublicKey, RSAPrivateKey)} or {@link #RSA512(RSAKeyProvider)}
     */
    @Deprecated
    public static Algorithm RSA512(RSAKey key) throws IllegalArgumentException {
        RSAPublicKey publicKey = key instanceof RSAPublicKey ? (RSAPublicKey) key : null;
        RSAPrivateKey privateKey = key instanceof RSAPrivateKey ? (RSAPrivateKey) key : null;
        return RSA512(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using RSA/ECB/PKCS1Padding (JWE RSA1_5) for JWE encryption
     * @param keyProvider the provider of the Public Key and Private Key for the encryption and decryption instance.
     * @return a valid RSA1_5 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null
     */
    public static Algorithm RSA1_5(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RSA1_5", "RSA/ECB/PKCS1Padding", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using RSA/ECB/PKCS1Padding (JWE RSA1_5) for JWE encryption
     * @param publicKey  the key to use in the encryption instance.
     * @param privateKey the key to use in the decryption instance.
     * @return a valid RSA1_5 Algorithm
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSA1_5(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSA1_5(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using RSA/ECB/OAEPWithSHA-1AndMGF1Padding (JWE RSA-OAEP) for JWE encryption
     * @param keyProvider the provider of the Public Key and Private Key for the encryption and decryption instance
     * @return a valid RSAOAEP Algorithm
     * @throws IllegalArgumentException if the provided Key is null
     */
    public static Algorithm RSAOAEP(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RSA-OAEP", "RSA/ECB/OAEPWithSHA-1AndMGF1Padding", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using RSA/ECB/OAEPWithSHA-1AndMGF1Padding (JWE RSA-OAEP) for JWE encryption
     * @param publicKey  the key to use in the encryption instance.
     * @param privateKey the key to use in the decryption instance.
     * @return a valid RSAOAEP Algorithm
     * @throws IllegalArgumentException if both provided Keys are null.
     */
    public static Algorithm RSAOAEP(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSAOAEP(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using RSA/ECB/OAEPWithSHA-1AndMGF1Padding (JWE RSA-OAEP-256) for JWE encryption
     * @param keyProvider the provider of the Public Key and Private Key for the encryption and decryption instance
     * @return a valid RSAOAEP256 Algorithm
     * @throws IllegalArgumentException if the provided Key is null
     */
    public static Algorithm RSAOAEP256(RSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new RSAAlgorithm("RSA-OAEP-256", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", keyProvider);
    }

    /**
     * Creates a new Algorithm instance using RSA/ECB/OAEPWithSHA-1AndMGF1Padding (JWE RSA-OAEP-256) for JWE encryption
     * @param publicKey  the key to use in the encryption instance.
     * @param privateKey the key to use in the decryption instance.
     * @return a valid RSAOAEP256 Algorithm
     * @throws IllegalArgumentException  if both provided Keys are null.
     */
    public static Algorithm RSAOAEP256(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws IllegalArgumentException {
        return RSAOAEP256(RSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC256 Algorithm.
     * @throws IllegalArgumentException     if the provided Secret is null.
     * @throws UnsupportedEncodingException if the current Java platform implementation doesn't support the UTF-8 character encoding.
     */
    public static Algorithm HMAC256(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC384 Algorithm.
     * @throws IllegalArgumentException     if the provided Secret is null.
     * @throws UnsupportedEncodingException if the current Java platform implementation doesn't support the UTF-8 character encoding.
     */
    public static Algorithm HMAC384(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
     *
     * @param secret the secret to use in the verify or signing instance.
     * @return a valid HMAC512 Algorithm.
     * @throws IllegalArgumentException     if the provided Secret is null.
     * @throws UnsupportedEncodingException if the current Java platform implementation doesn't support the UTF-8 character encoding.
     */
    public static Algorithm HMAC512(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA256. Tokens specify this as "HS256".
     *
     * @param secret the secret bytes to use in the verify or signing instance.
     * @return a valid HMAC256 Algorithm.
     * @throws IllegalArgumentException if the provided Secret is null.
     */
    public static Algorithm HMAC256(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS256", "HmacSHA256", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA384. Tokens specify this as "HS384".
     *
     * @param secret the secret bytes to use in the verify or signing instance.
     * @return a valid HMAC384 Algorithm.
     * @throws IllegalArgumentException if the provided Secret is null.
     */
    public static Algorithm HMAC384(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS384", "HmacSHA384", secret);
    }

    /**
     * Creates a new Algorithm instance using HmacSHA512. Tokens specify this as "HS512".
     *
     * @param secret the secret bytes to use in the verify or signing instance.
     * @return a valid HMAC512 Algorithm.
     * @throws IllegalArgumentException if the provided Secret is null.
     */
    public static Algorithm HMAC512(byte[] secret) throws IllegalArgumentException {
        return new HMACAlgorithm("HS512", "HmacSHA512", secret);
    }

    /**
     * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid ECDSA256 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm ECDSA256(ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES256", "SHA256withECDSA", 32, keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid ECDSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm ECDSA256(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return ECDSA256(ECDSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using SHA256withECDSA. Tokens specify this as "ES256".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA256 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #ECDSA256(ECPublicKey, ECPrivateKey)} or {@link #ECDSA256(ECDSAKeyProvider)}
     */
    @Deprecated
    public static Algorithm ECDSA256(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return ECDSA256(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid ECDSA384 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm ECDSA384(ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES384", "SHA384withECDSA", 48, keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid ECDSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm ECDSA384(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return ECDSA384(ECDSAAlgorithm.providerForKeys(publicKey, privateKey));
    }

    /**
     * Creates a new Algorithm instance using SHA384withECDSA. Tokens specify this as "ES384".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA384 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #ECDSA384(ECPublicKey, ECPrivateKey)} or {@link #ECDSA384(ECDSAKeyProvider)}
     */
    @Deprecated
    public static Algorithm ECDSA384(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return ECDSA384(publicKey, privateKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
     *
     * @param keyProvider the provider of the Public Key and Private Key for the verify and signing instance.
     * @return a valid ECDSA512 Algorithm.
     * @throws IllegalArgumentException if the Key Provider is null.
     */
    public static Algorithm ECDSA512(ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        return new ECDSAAlgorithm("ES512", "SHA512withECDSA", 66, keyProvider);
    }

    /**
     * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
     *
     * @param publicKey  the key to use in the verify instance.
     * @param privateKey the key to use in the signing instance.
     * @return a valid ECDSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     */
    public static Algorithm ECDSA512(ECPublicKey publicKey, ECPrivateKey privateKey) throws IllegalArgumentException {
        return ECDSA512(ECDSAAlgorithm.providerForKeys(publicKey, privateKey));
    }


    public static Algorithm A128CBC_HS256(CipherParams cipherParams) throws IllegalArgumentException {
        return new AESHSAlgorithm("A128CBC-HS256", "AES/CBC/PKCS5Padding", cipherParams);
    }

    public static Algorithm A192CBC_HS384(CipherParams cipherParams) throws IllegalArgumentException {
        return new AESHSAlgorithm("A192CBC-HS384", "AES/CBC/PKCS5Padding", cipherParams);
    }

    public static Algorithm A256BC_HS512(CipherParams cipherParams) throws IllegalArgumentException {
        return new AESHSAlgorithm("A256CBC-HS512", "AES/CBC/PKCS5Padding", cipherParams);
    }

    public static Algorithm A128GCM(CipherParams cipherParams) throws IllegalArgumentException {
        return new AESGCMAlgorithm("A128GCM", "AES/GCM/NoPadding", cipherParams);
    }

    public static Algorithm A192GCM(CipherParams cipherParams) throws IllegalArgumentException {
        return new AESGCMAlgorithm("A192GCM", "AES/GCM/NoPadding", cipherParams);
    }

    public static Algorithm A256GCM(CipherParams cipherParams) throws IllegalArgumentException {
        return new AESGCMAlgorithm("A256GCM", "AES/GCM/NoPadding", cipherParams);
    }

    public static Algorithm ECDH_ES(ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return new ECDHESAlgorithm("ECDH-ES", "ECDH", senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES(ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return ECDH_ES(ECDSAAlgorithm.providerForKeys(senderPublicKey, senderPrivateKey), ECDSAAlgorithm.providerForKeys(receiverPublicKey, null), partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES(ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId) throws  IllegalArgumentException {
        int keydataLen = getAlgorithmKeydataLen(algId);
        return new ECDHESAlgorithm("ECDH-ES", "ECDH", senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES(ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId) throws  IllegalArgumentException {
        int keydataLen = getAlgorithmKeydataLen(algId);
        return ECDH_ES(ECDSAAlgorithm.providerForKeys(senderPublicKey, senderPrivateKey), ECDSAAlgorithm.providerForKeys(receiverPublicKey, null), partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES_A128KW(ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return new ECDHESKeyWrapAlgorithm("ECDH-ES+A128KW", "ECDH", senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES_A128KW(ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return ECDH_ES_A128KW(ECDSAAlgorithm.providerForKeys(senderPublicKey, senderPrivateKey), ECDSAAlgorithm.providerForKeys(receiverPublicKey, null), partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES_A192KW(ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return new ECDHESKeyWrapAlgorithm("ECDH-ES+A192KW", "ECDH", senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES_A192KW(ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return ECDH_ES_A192KW(ECDSAAlgorithm.providerForKeys(senderPublicKey, senderPrivateKey), ECDSAAlgorithm.providerForKeys(receiverPublicKey, null), partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES_A256KW(ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return new ECDHESKeyWrapAlgorithm("ECDH-ES+A256KW", "ECDH", senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm ECDH_ES_A256KW(ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws  IllegalArgumentException {
        return ECDH_ES_A256KW(ECDSAAlgorithm.providerForKeys(senderPublicKey, senderPrivateKey), ECDSAAlgorithm.providerForKeys(receiverPublicKey, null), partyUInfo, partyVInfo, algId, keydataLen);
    }

    public static Algorithm AES128Keywrap(byte[] keywrapKey) throws  IllegalArgumentException {
        return new AESKeyWrapAlgorithm("A128KW", "AESWrap", keywrapKey);
    }

    public static Algorithm AES192Keywrap(byte[] keywrapKey) throws  IllegalArgumentException {
        return new AESKeyWrapAlgorithm("A192KW", "AESWrap", keywrapKey);
    }

    public static Algorithm AES256Keywrap(byte[] keywrapKey) throws  IllegalArgumentException {
        return new AESKeyWrapAlgorithm("A256KW", "AESWrap", keywrapKey);
    }

    /**
     * Creates a new Algorithm instance using SHA512withECDSA. Tokens specify this as "ES512".
     *
     * @param key the key to use in the verify or signing instance.
     * @return a valid ECDSA512 Algorithm.
     * @throws IllegalArgumentException if the provided Key is null.
     * @deprecated use {@link #ECDSA512(ECPublicKey, ECPrivateKey)} or {@link #ECDSA512(ECDSAKeyProvider)}
     */
    @Deprecated
    public static Algorithm ECDSA512(ECKey key) throws IllegalArgumentException {
        ECPublicKey publicKey = key instanceof ECPublicKey ? (ECPublicKey) key : null;
        ECPrivateKey privateKey = key instanceof ECPrivateKey ? (ECPrivateKey) key : null;
        return ECDSA512(publicKey, privateKey);
    }


    public static Algorithm none() {
        return new NoneAlgorithm();
    }

    /**
     * Gets the number of bits required for the key for the specified algorithm
     * @param alg JWA algorithm string
     * @return number of bits required
     */
    public static int getAlgorithmKeydataLen(String alg) {
        int requiredLen = 0;
        if(("A128CBC-HS256").equals(alg)) {
            requiredLen = 256;
        } else if("A192CBC-HS384".equals(alg)) {
            requiredLen = 384;
        } else if("A256CBC-HS512".equals(alg)) {
            requiredLen = 512;
        } else if("A128GCM".equals(alg)) {
            requiredLen = 128;
        } else if("A192GCM".equals(alg)) {
            requiredLen = 192;
        } else if("A256GCM".equals(alg)) {
            requiredLen = 256;
        } else if("A128KW".equals(alg)) {
            requiredLen = 128;
        } else if("A192KW".equals(alg)) {
            requiredLen = 192;
        } else if("A256KW".equals(alg)) {
            requiredLen = 256;
        } else if("ECDH-ES+A128KW".equals(alg)) {
            requiredLen = 128;
        } else if("ECDH-ES+A192KW".equals(alg)) {
            requiredLen = 192;
        } else if("ECDH-ES+A256KW".equals(alg)) {
            requiredLen = 256;
        }
        return requiredLen;
    }

    public static Algorithm getContentEncryptionAlg(String algorithm, CipherParams cipherParams) {
        if("A128CBC-HS256".equals(algorithm)) {
            return A128CBC_HS256(cipherParams);
        } else if("A192CBC-HS384".equals(algorithm)) {
            return A192CBC_HS384(cipherParams);
        } else if("A256CBC-HS512".equals(algorithm)) {
            return A256BC_HS512(cipherParams);
        } else if("A128GCM".equals(algorithm)) {
            return A128GCM(cipherParams);
        } else if("A192GCM".equals(algorithm)) {
            return A192GCM(cipherParams);
        } else if("A256GCM".equals(algorithm)) {
            return A256GCM(cipherParams);
        } else {
            return null;
        }
    }

    public static Algorithm getKeyWrapAlg(String algorithm, byte[] key) {
        if("A128KW".equals(algorithm)) {
            return AES128Keywrap(key);
        } else if("A192KW".equals(algorithm)) {
            return AES192Keywrap(key);
        } else if("A256KW".equals(algorithm)) {
            return AES256Keywrap(key);
        } else {
            return null;
        }
    }

    public static Algorithm getECDHES_KeyWrapAlg(String algorithm, ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId, int keydataLen) {
        if("ECDH-ES+A128KW".equals(algorithm)) {
            return ECDH_ES_A128KW(senderPrivateKey, senderPublicKey, receiverPublicKey, partyUInfo, partyVInfo, algId, keydataLen);
        } else if("ECDH-ES+A192KW".equals(algorithm)) {
            return ECDH_ES_A192KW(senderPrivateKey, senderPublicKey, receiverPublicKey, partyUInfo, partyVInfo, algId, keydataLen);
        } else if("ECDH-ES+A256KW".equals(algorithm)) {
            return ECDH_ES_A256KW(senderPrivateKey, senderPublicKey, receiverPublicKey, partyUInfo, partyVInfo, algId, keydataLen);
        } else {
            return null;
        }
    }

    public static Algorithm getECDHES_KeyWrapAlg(String algorithm, ECPrivateKey senderPrivateKey, ECPublicKey senderPublicKey, ECPublicKey receiverPublicKey, String partyUInfo, String partyVInfo, String algId) {
        int keydataLen = getAlgorithmKeydataLen(algId);
        return getECDHES_KeyWrapAlg(algorithm, senderPrivateKey, senderPublicKey, receiverPublicKey, partyUInfo, partyVInfo, algId, keydataLen);
    }

    protected Algorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    /**
     * Getter for the Id of the Private Key used to sign the tokens. This is usually specified as the `kid` claim in the Header.
     *
     * @return the Key Id that identifies the Signing Key or null if it's not specified.
     */
    public String getSigningKeyId() {
        return null;
    }

    /**
     * Getter for the name of this Algorithm, as defined in the JWT Standard. i.e. "HS256"
     *
     * @return the algorithm name.
     */
    public String getName() {
        return name;
    }

    /**
     * Getter for the description of this Algorithm, required when instantiating a Mac or Signature object. i.e. "HmacSHA256"
     *
     * @return the algorithm description.
     */
    String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description;
    }

    /**
     * Verify the given token using this Algorithm instance.
     *
     * @param jwt the already decoded JWT that it's going to be verified.
     * @throws SignatureVerificationException if the Token's Signature is invalid, meaning that it doesn't match the signatureBytes, or if the Key is invalid.
     */
    public abstract void verify(DecodedJWT jwt) throws SignatureVerificationException;

    /**
     * Sign the given content using this Algorithm instance.
     *
     * @param contentBytes an array of bytes representing the base64 encoded content to be verified against the signature.
     * @return the signature in a base64 encoded array of bytes
     * @throws SignatureGenerationException if the Key is invalid.
     */
    public abstract byte[] sign(byte[] contentBytes) throws SignatureGenerationException;


    public byte[] encrypt(byte[] contentBytes)throws EncryptionException {
        throw new EncryptionException(this, "Encryption is not supported");
    }

    public byte[] decrypt(byte[] cipherText) throws DecryptionException {
        throw new DecryptionException(this, "Decryption is not supported");
    }

    public AuthenticatedCipherText encrypt(byte[] contentBytes, byte[] aad) throws EncryptionException {
        throw new EncryptionException(this, "Encryption is not supported");
    }

    public byte[] decrypt(byte[] cipherText, byte[] authTag, byte[] aad) throws DecryptionException {
        throw new DecryptionException(this, "Decryption is not supported");
    }

    public byte[] generateAgreementKey() throws KeyAgreementException {
        throw new KeyAgreementException(this, "Key agreement is not supported");
    }

    public byte[] generateDerivedKey() throws KeyAgreementException {
        throw new KeyAgreementException(this, "Derived key agreement is not supported");
    }


    public byte[] wrap(byte[] contentBytes)throws EncryptionException {
        throw new EncryptionException(this, "Key Wrap is not supported");
    }

    public byte[] unwrap(byte[] cipherText) throws DecryptionException {
        throw new DecryptionException(this, "Key Unwrap is not supported");
    }

    public Map<String, Object> getPubInfo() {
        return Collections.emptyMap();
    }

}
