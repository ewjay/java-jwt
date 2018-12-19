package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;

/**
 * Abstract JWE encryption algorithm class for performing JWE key encryption and decryption operations
 */
public abstract class JWEKeyEncryptionAlgorithm extends JWEAlgorithm {

    protected JWEKeyEncryptionAlgorithm(String name, String description) {
        super(name, description);
    }

    /**
     * Encrypts a key
     * @param contentBytes array of bytes to be encrypted
     * @return encrypted content as a byte array
     * @throws EncryptionException if encryption fails
     */
    public abstract byte[] encrypt(byte[] contentBytes)throws EncryptionException;

    /**
     * Decrypts a key
     * @param cipherText encrypted key to be decrypted
     * @return decrypted key as a byte array
     * @throws DecryptionException if decryption fails
     */
    public abstract byte[] decrypt(byte[] cipherText) throws DecryptionException;

}
