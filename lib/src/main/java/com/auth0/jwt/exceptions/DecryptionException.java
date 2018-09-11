package com.auth0.jwt.exceptions;

import com.auth0.jwt.algorithms.Algorithm;

public class DecryptionException extends JWTVerificationException {

    public DecryptionException(Algorithm algorithm, String description) {
        super("The plain text couldn't be generated when decrypting using the Algorithm: " + algorithm + " - " + description, null);
    }

    public DecryptionException(Algorithm algorithm, Throwable cause) {
        super("The plain text couldn't be generated when decrypting using the Algorithm: " + algorithm, cause);
    }
}
