package com.auth0.jwt;

import com.auth0.jwt.algorithms.AESGCMAlgorithm;
import com.auth0.jwt.algorithms.AESHSAlgorithm;
import com.auth0.jwt.algorithms.AESKeyWrapAlgorithm;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.AuthenticatedCipherText;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.ECDHESAlgorithm;
import com.auth0.jwt.algorithms.ECDHESKeyWrapAlgorithm;
import com.auth0.jwt.algorithms.JWEContentEncryptionAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyAgreementAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyEncryptionAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyWrapAlgorithm;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.impl.PayloadSerializer;
import com.auth0.jwt.impl.PublicClaims;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.Deflater;

/**
 * JWE class for performing encryption
 */
public class JWTEncryptor {
    private Algorithm alg;
    private Algorithm encAlg;
    private byte[] headerBytes;
    private byte[] payloadBytes;


    public JWTEncryptor(Algorithm alg, Algorithm encAlg, Map<String, Object> header, Map<String, Object> payload) throws  JWTCreationException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(ClaimsHolder.class, new PayloadSerializer());
            mapper.registerModule(module);
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
            this.headerBytes = mapper.writeValueAsBytes(header);
            this.payloadBytes = mapper.writeValueAsBytes(payload);
            this.alg = alg;
            this.encAlg = encAlg;
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }

    public JWTEncryptor(Algorithm alg, Algorithm encAlg, Map<String, Object> header, byte[] payloadBytes) throws  JWTCreationException {
        try {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(ClaimsHolder.class, new PayloadSerializer());
            mapper.registerModule(module);
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
            this.headerBytes = mapper.writeValueAsBytes(header);
            this.payloadBytes = payloadBytes;
            this.alg = alg;
            this.encAlg = encAlg;
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }
    
    public JWTEncryptor(Algorithm alg, Algorithm encAlg, byte[] headerBytes, byte[] payloadBytes) {
        this.alg = alg;
        this.encAlg = encAlg;
        this.headerBytes = headerBytes;
        this.payloadBytes = payloadBytes;
    }

    /**
     * Initialize a JWTCreator instance.
     *
     * @return a JWTCreator.Builder instance to configure.
     */
    public static JWTEncryptor.Builder init() {
        return new JWTEncryptor.Builder();
    }

    /**
     * The Builder class holds the Claims that defines the JWT to be created.
     */
    public static class Builder {
        private Map<String, Object> headerClaims;
        private byte[] payload;

        Builder() {
            this.headerClaims = new HashMap<>();
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        public JWTEncryptor.Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = new HashMap<>(headerClaims);
            return this;
        }

        /**
         * Add a specific Key Id ("kid") claim to the Header.
         * If the {@link Algorithm} used to sign this token was instantiated with a KeyProvider, the 'kid' value will be taken from that provider and this one will be ignored.
         *
         * @param keyId the Key Id value.
         * @return this same Builder instance.
         */
        public JWTEncryptor.Builder withKeyId(String keyId) {
            this.headerClaims.put(PublicClaims.KEY_ID, keyId);
            return this;
        }

        /**
         * Add the content-type ("cty") claim to the Header to indicate Payload content-type
         * @param contentType the content-type string
         * @return this same Builder instance
         */
        public JWTEncryptor.Builder withContentType(String contentType) {
            this.headerClaims.put(PublicClaims.CONTENT_TYPE, contentType);
            return this;
        }

        /**
         * Add the type ("typ") claim to the Header to indicate entire JWT type
         * @param type the type string
         * @return this same Builder instance
         */
        public JWTEncryptor.Builder withType(String type) {
            this.headerClaims.put(PublicClaims.TYPE, type);
            return this;
        }


        /**
         * Add the specified claim name and value to the Header
         * @param name name of the claim
         * @param value value of the claim
         * @return this same Builder instance
         */
        public JWTEncryptor.Builder withHeaderClaim(String name, String value) {
            assertNonNull(name);
            addHeaderClaim(name, value);
            return this;
        }

        /**
         * Set the payloadBytes
         * @param payload bytes representing the payloadBytes
         * @return this same Builder instance
         */
        public JWTEncryptor.Builder withPayload(byte[] payload) {
            this.payload = payload;
            return this;
        }

        /**
         * Creates a new JWT and encrypts it with the given key algorithm and enc algorithm
         * @param algAlgorithm
         * @param encAlg
         * @return a new JWT token
         * @throws IllegalArgumentException
         * @throws JWTCreationException
         */
        public String encrypt(Algorithm algAlgorithm, Algorithm encAlg) throws IllegalArgumentException, JWTCreationException {
            return encrypt(algAlgorithm, encAlg, false);
        }


        /**
         * Creates a new JWT, optionally deflates the payload and then encrypts it with the given
         * key algorithm and enc algorithm
         * @param algAlgorithm
         * @param encAlg
         * @return a new JWT token
         * @throws IllegalArgumentException
         * @throws JWTCreationException
         */
        public String encrypt(Algorithm algAlgorithm, Algorithm encAlg, boolean deflate)
            throws IllegalArgumentException, JWTCreationException {
            if (algAlgorithm == null) {
                throw new IllegalArgumentException("The alg Algorithm cannot be null.");
            }
            if (encAlg == null) {
                throw new IllegalArgumentException("The enc Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algAlgorithm.getName());
            headerClaims.put(PublicClaims.ENC_ALGORITHM, encAlg.getName());
            headerClaims.put(PublicClaims.TYPE, "JWT");
            headerClaims.putAll(algAlgorithm.getPubInfo());
            if(deflate) {
                headerClaims.put(PublicClaims.ZIP, "DEF");
            }
            return new JWTEncryptor(algAlgorithm, encAlg, headerClaims, payload).encrypt(deflate);
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }
        
        private void addHeaderClaim(String name, Object value) {
            if (value == null) {
                headerClaims.remove(name);
                return;
            }
            headerClaims.put(name, value);
        }
    }

    private byte[] deflate(byte[] input) {
        System.out.printf("uncompressed output = %s\n", Hex.encodeHexString(input));
        byte[] output = new byte[512];
        Deflater compresser = new Deflater(Deflater.BEST_COMPRESSION);
        compresser.setInput(input);
        compresser.finish();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        while(!compresser.finished()) {
            int compressedDataLength = compresser.deflate(output);
            byteArrayOutputStream.write(output, 0, compressedDataLength);
        }
        compresser.end();
        return byteArrayOutputStream.toByteArray();

    }

    public String encrypt() throws EncryptionException {
        return encrypt(false);
    }

    public String encrypt(boolean deflate) throws EncryptionException{
        String encodedHeader = Base64.encodeBase64URLSafeString(headerBytes);
        /*
          BASE64URL(UTF8(JWE Protected Header)) || '.' ||
          BASE64URL(JWE Encrypted Key) || '.' ||
          BASE64URL(JWE Initialization Vector) || '.' ||
          BASE64URL(JWE Ciphertext) || '.' ||
          BASE64URL(JWE Authentication Tag)
         */

        byte[] encryptedKey = new byte[0];
        String encodedKey;
        AESHSAlgorithm aeshsAlgorithm;
        AESGCMAlgorithm aesgcmAlgorithm;
        CipherParams cipherParams;
        if(encAlg instanceof AESHSAlgorithm) {
            aeshsAlgorithm = (AESHSAlgorithm) encAlg;
            // cipherParams should hold values for keyagreement algs also
            cipherParams = aeshsAlgorithm.getCipherParams();
        } else if(encAlg instanceof  AESGCMAlgorithm) {
            aesgcmAlgorithm = (AESGCMAlgorithm) encAlg;
            cipherParams = aesgcmAlgorithm.getCipherParams();
        } else {
            throw new EncryptionException(encAlg, "Unsupported enc algorithm");
        }
        if(alg instanceof JWEKeyAgreementAlgorithm) {
            encodedKey = "";
        } else {
            // key encryption or key wrap
            if(alg instanceof JWEKeyWrapAlgorithm) {
                encryptedKey = ((JWEKeyWrapAlgorithm)alg).wrap(cipherParams.getMacEncKey());
            } else {
                encryptedKey = ((JWEKeyEncryptionAlgorithm)alg).encrypt(cipherParams.getMacEncKey());
            }
            encodedKey = Base64.encodeBase64URLSafeString(encryptedKey);
        }
        String encodeIV = Base64.encodeBase64URLSafeString(cipherParams.getIv());

        if(deflate) {
            // Compress the bytes
            payloadBytes = deflate(payloadBytes);
            System.out.printf("compressed output = %s\n", Hex.encodeHexString(payloadBytes));
        }
        AuthenticatedCipherText authenticatedCipherText = ((JWEContentEncryptionAlgorithm)encAlg).encrypt(payloadBytes, StringUtils.getBytesUtf8(encodedHeader));
        String encodeCipherText = authenticatedCipherText.getBase64urlCipherText();
        String encodedTag = authenticatedCipherText.getBase64urlTag();
        return String.format("%s.%s.%s.%s.%s", encodedHeader, encodedKey, encodeIV, encodeCipherText, encodedTag);
    }

}
