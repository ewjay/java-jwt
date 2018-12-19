package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.KeyAgreementException;

/**
 * Abstract JWE encryption algorithm class for performing JWE key wrap operations
 */
public abstract class JWEKeyWrapAlgorithm extends JWEAlgorithm {

    protected JWEKeyWrapAlgorithm(String name, String description) {
        super(name, description);
    }

    /**
     * Wraps a key
     * @param contentBytes key bytes to be wrapped
     * @return wrapped key as a byte array
     * @throws EncryptionException if key wrap operations fail
     */
    public abstract byte[] wrap(byte[] contentBytes)throws EncryptionException;

    /**
     * Unwraps a key
     * @param cipherText wrapped key to be unwrapped
     * @return unwrapped key as a byte array
     * @throws DecryptionException if key unwrap operations fail
     */
    public abstract byte[] unwrap(byte[] cipherText) throws DecryptionException;
}
