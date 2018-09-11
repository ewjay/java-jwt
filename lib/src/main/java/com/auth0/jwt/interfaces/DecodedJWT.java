package com.auth0.jwt.interfaces;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.JWTCreationException;

import java.io.StringWriter;

/**
 * Class that represents a Json Web Token that was decoded from it's string representation.
 */
public interface DecodedJWT extends Payload, Header {
    /**
     * Getter for the String Token used to create this JWT instance.
     *
     * @return the String Token.
     */
    String getToken();

    /**
     * Getter for the Header contained in the JWT as a Base64 encoded String.
     * This represents the first part of the token.
     *
     * @return the Header of the JWT.
     */
    String getHeader();

    /**
     * Getter for the Payload contained in the JWT as a Base64 encoded String.
     * This represents the second part of the token.
     *
     * @return the Payload of the JWT.
     */
    String getPayload();

    /**
     * Getter for the Signature contained in the JWT as a Base64 encoded String.
     * This represents the third part of the token.
     *
     * @return the Signature of the JWT.
     */
    String getSignature();


    /**
     * Indicates whether the JWT is an encrypted JWT(JWE)
     * @return true/false
     */
    boolean isJWE();


    /**
     * Performs decryption if the JWT is a JWE
     * @param algorithm Algorithm class to decrypt the content encryption key
     * @return a DecodedJWT if the payload is another JWT, otherwise null
     */
    DecodedJWT decrypt(Algorithm algorithm) throws DecryptionException;

    /**
     * Getter for the authentication tag if the JWT is a JWE
     * his represents the fifth part of the token.
     * @return part
     */
    String getAuthenticationTag();


    /**
     * Getter for the IV if the JWT is a JWE
     * his represents the third part of the token.
     * @return
     */
    String getIV();

    /**
     * Getter for the encrypted key part iff the JWT is a JWE
     * This represents the second part of the token.
     * @return
     */
    String getKey();

    /**
     * Getter for the ciphertext if the JWT is a JWE
     * This represents the fourth part of the token.
     * @return
     */
    String getCipherText();
}
