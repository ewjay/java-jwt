package com.auth0.jwt;

import com.auth0.jwt.algorithms.AESKeyWrapAlgorithm;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.algorithms.CipherParams;
import com.auth0.jwt.algorithms.ECDHESAlgorithm;
import com.auth0.jwt.algorithms.ECDHESKeyWrapAlgorithm;
import com.auth0.jwt.algorithms.JWEContentEncryptionAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyAgreementAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyEncryptionAlgorithm;
import com.auth0.jwt.algorithms.JWEKeyWrapAlgorithm;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.impl.PublicClaims;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * JWE class for performing decryption
 */
public class JWTDecryptor {
    private Algorithm keyDecryptionAlg;

    /**
     * Constructs a new JWTDecryptor for performing decryption
     * @param keyDecryptionAlg algorithm used for key decryption or key agreement, must match the
     *                         'alg' parameter specified in the JWE
     */
    public JWTDecryptor(Algorithm keyDecryptionAlg) {
        this.keyDecryptionAlg = keyDecryptionAlg;
    }

    private byte[] inflate(byte[] input) throws  DataFormatException{
        Inflater decompresser = new Inflater();
        decompresser.setInput(input);
        byte[] result = new byte[512];
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        while(!decompresser.finished()) {
            int resultLength = decompresser.inflate(result);
            byteArrayOutputStream.write(result, 0, resultLength);
        }
        decompresser.end();
        return byteArrayOutputStream.toByteArray();
    }

    /**
     * Decrypts a JWE
     * @param jwe JWE string
     * @return byte array representing the decrypted payload contents
     * @throws DecryptionException if decryption fails(key decryption error, invalid algorithm,
     *                             compression failure)
     */
    public byte[] decrypt(String jwe) throws DecryptionException {
        if(keyDecryptionAlg == null) {
            throw new DecryptionException(keyDecryptionAlg, "Algorithm is null");
        }
        DecodedJWT decodedJWT = JWT.decode(jwe);
        String algAlgId = decodedJWT.getAlgorithm();
        if(!decodedJWT.getAlgorithm().equals(keyDecryptionAlg.getName())) {
            throw new DecryptionException(keyDecryptionAlg, "alg Algorithm mismatch");
        }
        byte[] encryptedKey = Base64.decodeBase64(decodedJWT.getKey());
        byte[] iv = Base64.decodeBase64(decodedJWT.getIV());
        byte[] tag = Base64.decodeBase64(decodedJWT.getAuthenticationTag());
        byte[] headerBytes = decodedJWT.getHeader().getBytes(StandardCharsets.UTF_8);
        byte[] cipherText = Base64.decodeBase64(decodedJWT.getCipherText());
        byte[] decryptedKey = new byte[0];

        if(keyDecryptionAlg instanceof JWEKeyAgreementAlgorithm) {
            try {
                decryptedKey = ((JWEKeyAgreementAlgorithm)keyDecryptionAlg).generateDerivedKey();
            } catch (KeyAgreementException e) {
                throw new DecryptionException(keyDecryptionAlg, e);
            }
        } else if(keyDecryptionAlg instanceof JWEKeyWrapAlgorithm) {
            decryptedKey = ((JWEKeyWrapAlgorithm)keyDecryptionAlg).unwrap(encryptedKey);
        } else {
            decryptedKey = ((JWEKeyEncryptionAlgorithm)keyDecryptionAlg).decrypt(encryptedKey);
        }
        List<String> aeshsAlgs = Arrays.asList("A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512");
        List<String> aesgcmAlgs = Arrays.asList("A128GCM", "A192GCM", "A256GCM");
        byte[] decryptedContent = null;
        if(aeshsAlgs.contains(decodedJWT.getEncAlgorithm())) {
            int mid = decryptedKey.length / 2;
            byte[] encKey = Arrays.copyOfRange(decryptedKey, mid, decryptedKey.length);
            byte[] macKey = Arrays.copyOfRange(decryptedKey, 0, mid);
            CipherParams cipherParams = new CipherParams(encKey, macKey, iv);
            JWEContentEncryptionAlgorithm encAlg = Algorithm.getContentEncryptionAlg(decodedJWT.getEncAlgorithm(),
                cipherParams);
            decryptedContent = encAlg.decrypt(cipherText, tag, headerBytes);
        } else if (aesgcmAlgs.contains(decodedJWT.getEncAlgorithm())) {
            CipherParams cipherParams = new CipherParams(decryptedKey, iv);
            JWEContentEncryptionAlgorithm encAlg = Algorithm.getContentEncryptionAlg(decodedJWT.getEncAlgorithm(),
                cipherParams);
            decryptedContent = encAlg.decrypt(cipherText, tag, headerBytes);
        } else {
            throw new DecryptionException(null, "Unknown enc alg : " + decodedJWT.getEncAlgorithm());
        }
        Claim zip = decodedJWT.getHeaderClaim(PublicClaims.ZIP);
        if(!(zip == null || zip.isNull())) {
            System.out.printf("decrypted output = %s\n", Hex.encodeHexString(decryptedContent));

            if("DEF".equals(zip.asString())) {
                // Decompress the bytes
                try {
                    byte[] inflated =  inflate(decryptedContent);
                    System.out.printf("inflated output = %s\n", Hex.encodeHexString(inflated));

                    return inflated;
                } catch(DataFormatException e) {
                    throw new DecryptionException(null, e);
                }
            } else {
                throw new DecryptionException(null, "Unsupported zip value " + zip.asString());
            }
        } else {
            return decryptedContent;
        }
    }



}
