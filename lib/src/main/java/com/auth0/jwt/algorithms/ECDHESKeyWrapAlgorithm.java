package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.DecryptionException;
import com.auth0.jwt.exceptions.EncryptionException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.msg.ECKey;
import com.auth0.msg.Utils;

import java.util.HashMap;
import java.util.Map;

public class ECDHESKeyWrapAlgorithm extends JWEKeyWrapAlgorithm {
    private JWEKeyAgreementAlgorithm keyAgreementAlgorithm;

    ECDHESKeyWrapAlgorithm(CryptoHelper crypto, String id, String algorithm, ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws IllegalArgumentException {
        super(id, algorithm);
        keyAgreementAlgorithm = (JWEKeyAgreementAlgorithm) Algorithm.ECDH_ES(senderProvider, receiverProvider, partyUInfo, partyVInfo, algId);
    }

    ECDHESKeyWrapAlgorithm(String id, String algorithm, ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    @Override
    public byte[] wrap(byte[] contentBytes) throws EncryptionException {
        try {
            byte[] kek = keyAgreementAlgorithm.generateDerivedKey();
            JWEKeyWrapAlgorithm algorithm = (JWEKeyWrapAlgorithm) Algorithm.getKeyWrapAlg(getName().substring(8), kek);
            if(algorithm != null) {
                return algorithm.wrap(contentBytes);
            } else {
                throw new EncryptionException(this, "Unexpected keywrap algorithm");
            }
        } catch(KeyAgreementException e) {
            throw new EncryptionException(this, e);
        }
    }

    @Override
    public byte[] unwrap(byte[] cipherText) throws DecryptionException {
        try {
            byte[] kek = keyAgreementAlgorithm.generateDerivedKey();
            JWEKeyWrapAlgorithm algorithm = (JWEKeyWrapAlgorithm)Algorithm.getKeyWrapAlg(getName().substring(8), kek);
            if(algorithm != null) {
                return algorithm.unwrap(cipherText);
            } else {
                throw new DecryptionException(this, "Unexpected keywrap algorithm");
            }
        } catch(KeyAgreementException e) {
            throw new DecryptionException(this, e);
        }
    }

    @Override
    public Map<String, Object> getPubInfo() {
        return keyAgreementAlgorithm.getPubInfo();
    }
}
