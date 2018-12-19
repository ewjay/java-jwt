package com.auth0.jwt.algorithms;

import com.auth0.jwt.algorithms.AuthenticatedCipherText;
import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;

/**
 * Abstract JWE encryption algorithm class for performing JWE content encryption and decryption operations
 */
public abstract class JWEContentEncryptionAlgorithm extends JWEAlgorithm {

    protected JWEContentEncryptionAlgorithm(String name, String description) {
        super(name, description);
    }

    /**
     * Encrypts payload content
     * @param contentBytes payload content to be encrypted
     * @param aad additional authentication data that will can be used for tamperproofing of encrypted content
     * @return AuthenticatedCipherText instance that contains the enrypted content and the authentication tag
     * @throws EncryptionException if encryption fails
     */
    public  abstract AuthenticatedCipherText encrypt(byte[] contentBytes, byte[] aad) throws EncryptionException;

    /**
     * Decrypts an encrypted payload
     * @param cipherText encrypted payload to be decrypted
     * @param authTag authentication tag that is used to check the encrypted content
     * @param aad additional authentication data that will can be used for validating the authentication tag
     * @return Decrypted content as a byte array
     * @throws DecryptionException if decryption fails
     */
    public  abstract byte[] decrypt(byte[] cipherText, byte[] authTag, byte[] aad) throws DecryptionException;

}
