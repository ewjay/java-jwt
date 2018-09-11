package com.auth0.jwt.exceptions;

import com.auth0.jwt.algorithms.Algorithm;

public class EncryptionException extends JWTCreationException {
    public EncryptionException(Algorithm algorithm, Throwable cause) {
        super("The cipher text couldn't be generated when encrypting using the Algorithm: " + algorithm, cause);
    }
}
