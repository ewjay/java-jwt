package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.KeyAgreementException;

/**
 * Abstract JWE encryption algorithm class for performing JWE key agreement operations
 */
public abstract class JWEKeyAgreementAlgorithm extends JWEAlgorithm {

    protected JWEKeyAgreementAlgorithm(String name, String description) {
        super(name, description);
    }

    /**
     * Generates a content encryption key using key agreement
     * @return agreed key as a byte array
     * @throws KeyAgreementException
     */
    public  abstract byte[] generateAgreementKey() throws KeyAgreementException;

    /**
     *
     * @return
     * @throws KeyAgreementException
     */
    public  abstract byte[] generateDerivedKey() throws KeyAgreementException;
}
