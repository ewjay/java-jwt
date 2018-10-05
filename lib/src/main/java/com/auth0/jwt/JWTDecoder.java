package com.auth0.jwt;

import com.auth0.jwt.algorithms.AESKeyWrapAlgorithm;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.ECDHESAlgorithm;
import com.auth0.jwt.algorithms.ECDHESKeyWrapAlgorithm;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The JWTDecoder class holds the decode method to parse a given JWT token into it's JWT representation.
 */
@SuppressWarnings("WeakerAccess")
final class JWTDecoder implements DecodedJWT {

    private final String[] parts;
    private final Header header;
    private Payload payload;
    private final boolean isJWE;

    JWTDecoder(String jwt) throws JWTDecodeException {
        parts = TokenUtils.splitToken(jwt);
        if(parts.length == 5) {
            isJWE = true;
        } else {
            isJWE = false;
        }
        final JWTParser converter = new JWTParser();
        String headerJson;
        String payloadJson;
        try {
            headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
            if(!isJWE) {
                payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
            } else {
                payloadJson = "{}"; // JWE is encrypted so use empty JSON
            }
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
    }

    @Override
    public DecodedJWT decrypt(Algorithm algorithm) throws DecryptionException {

        /*
        if(algorithm == null) {
            throw new DecryptionException(algorithm, "Algorithm is null");
        }
        String algAlgId = getAlgorithm();
        if(!getAlgorithm().equals(algorithm.getName())) {
            throw new DecryptionException(algorithm, "alg Algorithm mismatch");
        }

        byte[] encryptedKey = Base64.decodeBase64(getKey());

        byte[] iv = Base64.decodeBase64(getIV());
        byte[] tag = Base64.decodeBase64(getAuthenticationTag());
        byte[] headerBytes = getHeader().getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = Base64.decodeBase64(getCipherText());
        byte[] decryptedKey = new byte[0];

        if(algorithm instanceof ECDHESAlgorithm && !(algorithm instanceof ECDHESKeyWrapAlgorithm)) {
            try {
                decryptedKey = algorithm.generateDerivedKey();
            } catch (KeyAgreementException e) {
                throw new DecryptionException(algorithm, e);
            }
        } else if(algorithm instanceof ECDHESKeyWrapAlgorithm ||
            algorithm instanceof AESKeyWrapAlgorithm) {
            decryptedKey = algorithm.unwrap(encryptedKey);
        } else {
            decryptedKey = algorithm.decrypt(encryptedKey);
        }
        List<String> aeshsAlgs = Arrays.asList("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512");
        List<String> aesgcmAlgs = Arrays.asList("A128GCM", "A192GCM", "A256GCM");
        if(aeshsAlgs.contains(getEncAlgorithm())) {

            int mid = decryptedKey.length / 2;
            byte[] encKey = Arrays.copyOfRange(decryptedKey, mid, decryptedKey.length);
            byte[] macKey = Arrays.copyOfRange(decryptedKey, 0, mid);
            CipherParams cipherParams = new CipherParams(encKey, macKey, iv);
            Algorithm encAlg = Algorithm.getContentEncryptionAlg(getEncAlgorithm(), cipherParams);
            byte[] plainText = encAlg.decrypt(cipherText, tag, headerBytes);
            String payloadStr = StringUtils.newStringUtf8(plainText);
            if("JWT".equals(getContentType())) {
                return JWT.decode(payloadStr);
            } else {
                final JWTParser converter = new JWTParser();
                payload = converter.parsePayload(payloadStr);
                Map<String, Claim> claims = payload.getClaims();
            }
        } else if (aesgcmAlgs.contains(getEncAlgorithm())) {
            CipherParams cipherParams = new CipherParams(decryptedKey, iv);
            Algorithm encAlg = Algorithm.getContentEncryptionAlg(getEncAlgorithm(), cipherParams);
            byte[] plainText = encAlg.decrypt(cipherText, tag, headerBytes);
            String payloadStr = StringUtils.newStringUtf8(plainText);
            if("JWT".equals(getContentType())) {
                return JWT.decode(payloadStr);
            } else {
                final JWTParser converter = new JWTParser();
                payload = converter.parsePayload(payloadStr);
                Map<String, Claim> claims = payload.getClaims();
            }
        }
        */

        byte[] plainText = new JWTDecryptor(algorithm).decrypt(getToken());
        String payloadStr = StringUtils.newStringUtf8(plainText);
        if("JWT".equals(getContentType())) {
            // payload is a JWT so just return decoded JWT instead of setting payload claims
            return JWT.decode(payloadStr);
        } else {
            final JWTParser converter = new JWTParser();
            payload = converter.parsePayload(payloadStr);
            Map<String, Claim> claims = payload.getClaims();
        }
        return null;
    }

    @Override
    public String getAlgorithm() {
        return header.getAlgorithm();
    }

    @Override
    public String getEncAlgorithm() {
        return header.getEncAlgorithm();
    }

    @Override
    public String getType() {
        return header.getType();
    }

    @Override
    public String getContentType() {
        return header.getContentType();
    }

    @Override
    public String getKeyId() {
        return header.getKeyId();
    }

    @Override
    public Claim getHeaderClaim(String name) {
        return header.getHeaderClaim(name);
    }

    @Override
    public String getIssuer() {
        return payload.getIssuer();
    }

    @Override
    public String getSubject() {
        return payload.getSubject();
    }

    @Override
    public List<String> getAudience() {
        return payload.getAudience();
    }

    @Override
    public Date getExpiresAt() {
        return payload.getExpiresAt();
    }

    @Override
    public Date getNotBefore() {
        return payload.getNotBefore();
    }

    @Override
    public Date getIssuedAt() {
        return payload.getIssuedAt();
    }

    @Override
    public String getId() {
        return payload.getId();
    }

    @Override
    public Claim getClaim(String name) {
        return payload.getClaim(name);
    }

    @Override
    public Map<String, Claim> getClaims() {
        return payload.getClaims();
    }

    @Override
    public boolean isJWE() {
        return isJWE;
    }

    @Override
    public String getHeader() {
        return parts[0];
    }

    @Override
    public String getPayload() {
        if(!isJWE) {
            return parts[1];
        }
        else {
            return null;
        }
    }

    @Override
    public String getSignature() {
        if(!isJWE) {
            return parts[2];
        } else {
            return null;
        }
    }

    @Override
    public String getKey() {
        if(isJWE) {
            return parts[1];
        } else {
            return null;
        }
    }

    @Override
    public String getIV() {
        if(isJWE) {
            return parts[2];
        } else {
            return null;
        }
    }

    @Override
    public String getCipherText() {
        if(isJWE) {
            return parts[3];
        } else {
            return null;
        }
    }

    @Override
    public String getAuthenticationTag() {
        if(isJWE) {
            return parts[4];
        } else {
            return null;
        }
    }

    @Override
    public String getToken() {
        if(isJWE) {
            return String.format("%s.%s.%s.%s.%s", parts[0], parts[1], parts[2], parts[3], parts[4]);
        } else {
            return String.format("%s.%s.%s", parts[0], parts[1], parts[2]);
        }
    }
}
