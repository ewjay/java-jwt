package com.auth0.jwt;

import com.auth0.jwt.algorithms.AESGCMAlgorithm;
import com.auth0.jwt.algorithms.AESHSAlgorithm;
import com.auth0.jwt.algorithms.AESKeyWrapAlgorithm;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.AuthenticatedCipherText;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.ECDHESAlgorithm;
import com.auth0.jwt.algorithms.ECDHESKeyWrapAlgorithm;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.impl.ClaimsHolder;
import com.auth0.jwt.impl.PayloadSerializer;
import com.auth0.jwt.impl.PublicClaims;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * The JWTCreator class holds the sign method to generate a complete JWT (with Signature) from a given Header and Payload content.
 */
@SuppressWarnings("WeakerAccess")
public final class JWTCreator {

    private final Algorithm algorithm;
    private final Algorithm encAlgorithm;
    private final String headerJson;
    private final String payloadJson;

    private JWTCreator(Algorithm algorithm, Algorithm encAlgorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this.algorithm = algorithm;
        this.encAlgorithm = encAlgorithm;
        try {
            ObjectMapper mapper = new ObjectMapper();
            SimpleModule module = new SimpleModule();
            module.addSerializer(ClaimsHolder.class, new PayloadSerializer());
            mapper.registerModule(module);
            mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
            headerJson = mapper.writeValueAsString(headerClaims);
            payloadJson = mapper.writeValueAsString(new ClaimsHolder(payloadClaims));
        } catch (JsonProcessingException e) {
            throw new JWTCreationException("Some of the Claims couldn't be converted to a valid JSON format.", e);
        }
    }

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this(algorithm, null, headerClaims, payloadClaims);
    }


    /**
     * Initialize a JWTCreator instance.
     *
     * @return a JWTCreator.Builder instance to configure.
     */
    static JWTCreator.Builder init() {
        return new Builder();
    }

    /**
     * The Builder class holds the Claims that defines the JWT to be created.
     */
    public static class Builder {
        private final Map<String, Object> payloadClaims;
        private Map<String, Object> headerClaims;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        public Builder withHeader(Map<String, Object> headerClaims) {
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
        public Builder withKeyId(String keyId) {
            this.headerClaims.put(PublicClaims.KEY_ID, keyId);
            return this;
        }

        /**
         * Add a specific Issuer ("iss") claim to the Payload.
         *
         * @param issuer the Issuer value.
         * @return this same Builder instance.
         */
        public Builder withIssuer(String issuer) {
            addClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        /**
         * Add a specific Subject ("sub") claim to the Payload.
         *
         * @param subject the Subject value.
         * @return this same Builder instance.
         */
        public Builder withSubject(String subject) {
            addClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        /**
         * Add a specific Audience ("aud") claim to the Payload.
         *
         * @param audience the Audience value.
         * @return this same Builder instance.
         */
        public Builder withAudience(String... audience) {
            addClaim(PublicClaims.AUDIENCE, audience);
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim to the Payload.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        public Builder withExpiresAt(Date expiresAt) {
            addClaim(PublicClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim to the Payload.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        public Builder withNotBefore(Date notBefore) {
            addClaim(PublicClaims.NOT_BEFORE, notBefore);
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim to the Payload.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        public Builder withIssuedAt(Date issuedAt) {
            addClaim(PublicClaims.ISSUED_AT, issuedAt);
            return this;
        }

        /**
         * Add a specific JWT Id ("jti") claim to the Payload.
         *
         * @param jwtId the Token Id value.
         * @return this same Builder instance.
         */
        public Builder withJWTId(String jwtId) {
            addClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public Builder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        /**
         * Creates a new JWT and signs is with the given algorithm
         *
         * @param algorithm used to sign the JWT
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algorithm.getName());
            headerClaims.put(PublicClaims.TYPE, "JWT");
            String signingKeyId = algorithm.getSigningKeyId();
            if (signingKeyId != null) {
                withKeyId(signingKeyId);
            }
            return new JWTCreator(algorithm, headerClaims, payloadClaims).sign();
        }


        /**
         * Creates a new JWT and encrypts it with the given key algorithm and enc algorithm
         * @param algAlgorithm
         * @param encAlgorithm
         * @return a new JWT token
         * @throws IllegalArgumentException
         * @throws JWTCreationException
         */
        public String encrypt(Algorithm algAlgorithm, Algorithm encAlgorithm) throws IllegalArgumentException, JWTCreationException {
            if (algAlgorithm == null) {
                throw new IllegalArgumentException("The alg Algorithm cannot be null.");
            }
            if (encAlgorithm == null) {
                throw new IllegalArgumentException("The enc Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algAlgorithm.getName());
            headerClaims.put(PublicClaims.ENC_ALGORITHM, encAlgorithm.getName());
            headerClaims.put(PublicClaims.TYPE, "JWT");
            headerClaims.putAll(algAlgorithm.getPubInfo());
            return new JWTCreator(algAlgorithm, encAlgorithm, headerClaims, payloadClaims).encrypt();
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addClaim(String name, Object value) {
            if (value == null) {
                payloadClaims.remove(name);
                return;
            }
            payloadClaims.put(name, value);
        }
    }

    private String sign() throws SignatureGenerationException {
        String header = Base64.encodeBase64URLSafeString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.encodeBase64URLSafeString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String content = String.format("%s.%s", header, payload);

        byte[] signatureBytes = algorithm.sign(content.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.encodeBase64URLSafeString((signatureBytes));

        return String.format("%s.%s", content, signature);
    }


    private String encrypt() throws EncryptionException {
        String header = Base64.encodeBase64URLSafeString(headerJson.getBytes(StandardCharsets.UTF_8));
        /*
          BASE64URL(UTF8(JWE Protected Header)) || '.' ||
          BASE64URL(JWE Encrypted Key) || '.' ||
          BASE64URL(JWE Initialization Vector) || '.' ||
          BASE64URL(JWE Ciphertext) || '.' ||
          BASE64URL(JWE Authentication Tag)
         */

        /*
        byte[] encryptedKey = new byte[0];
        String encodedKey;
        AESHSAlgorithm aeshsAlgorithm;
        AESGCMAlgorithm aesgcmAlgorithm;
        CipherParams cipherParams;
        if(encAlgorithm instanceof AESHSAlgorithm) {
            aeshsAlgorithm = (AESHSAlgorithm) encAlgorithm;
            // cipherParams should hold values for keyagreement algs also
            cipherParams = aeshsAlgorithm.getCipherParams();
        } else if(encAlgorithm instanceof  AESGCMAlgorithm) {
            aesgcmAlgorithm = (AESGCMAlgorithm) encAlgorithm;
            cipherParams = aesgcmAlgorithm.getCipherParams();
        } else {
            throw new EncryptionException(encAlgorithm, "Unsupported enc algorithm");
        }
        if(algorithm instanceof ECDHESAlgorithm && !(algorithm instanceof ECDHESKeyWrapAlgorithm)) {
            encodedKey = "";
        } else {
            // key encryption or key wrap
            if(algorithm instanceof AESKeyWrapAlgorithm ||
                algorithm instanceof ECDHESKeyWrapAlgorithm) {
                encryptedKey = algorithm.wrap(cipherParams.getMacEncKey());
            } else {
                encryptedKey = algorithm.encrypt(cipherParams.getMacEncKey());
            }
            encodedKey = Base64.encodeBase64URLSafeString(encryptedKey);
        }
        String encodeIV = Base64.encodeBase64URLSafeString(cipherParams.getIv());
        AuthenticatedCipherText authenticatedCipherText = encAlgorithm.encrypt(payloadJson.getBytes(StandardCharsets.UTF_8), header.getBytes(StandardCharsets.UTF_8));
        String encodeCipherText = authenticatedCipherText.getBase64urlCipherText();
        String encodedTag = authenticatedCipherText.getBase64urlTag();
        return String.format("%s.%s.%s.%s.%s", header, encodedKey, encodeIV, encodeCipherText, encodedTag);
        */
        return new JWTEncryptor(algorithm, encAlgorithm,
            headerJson.getBytes(StandardCharsets.UTF_8),
            payloadJson.getBytes(StandardCharsets.UTF_8)).encrypt();
    }

}
