package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;

/**
 * Abstract JWE encryption algorithm class for organizing the set of JWE algorithms
 * This class does not provide any functions other than to function as a base class
 * for the  specific JWE algorithms
 */
public abstract class JWEAlgorithm extends Algorithm {

    protected JWEAlgorithm(String name, String description) {
        super(name, description);
    }
}
