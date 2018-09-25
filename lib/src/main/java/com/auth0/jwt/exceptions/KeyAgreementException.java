package com.auth0.jwt.exceptions;

import com.auth0.jwt.algorithms.Algorithm;

public class KeyAgreementException extends Exception {
    public KeyAgreementException(Algorithm algorithm, String description) {
        super("The key agreement cannot be generated for algorithm :" + algorithm + " - " + description, null);
    }

    public KeyAgreementException(Algorithm algorithm, Throwable cause) {
        super("The key agreement cannot be generated for algorithm :" + algorithm, null);
    }
}
