package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.KDFException;
import com.auth0.jwt.exceptions.KeyAgreementException;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.msg.ECKey;
import com.auth0.msg.Utils;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class ECDHESAlgorithm extends JWEKeyAgreementAlgorithm {
    protected final ECDSAKeyProvider senderProvider;
    protected final ECDSAKeyProvider receiverProvider;
    protected final CryptoHelper crypto;
    protected final String partyUInfo;
    protected final String partyVInfo;
    protected final String algId;
    protected final int keydataLen;

    ECDHESAlgorithm(CryptoHelper crypto, String id, String algorithm, ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws IllegalArgumentException {
        super(id, algorithm);
        if (senderProvider == null || senderProvider.getPrivateKey() == null) {
            throw new IllegalArgumentException("The sender's private key cannot be null.");
        }
        this.senderProvider = senderProvider;
        if (receiverProvider == null || receiverProvider.getPublicKeyById(null) == null) {
            throw new IllegalArgumentException("The receiver's public key cannot be null.");
        }
        this.receiverProvider = receiverProvider;
        this.crypto = crypto;
        this.partyUInfo = partyUInfo;
        this.partyVInfo = partyVInfo;
        this.algId = algId;
        if("A128CBC-HS256".equals(algId)) {
            keydataLen = 256;
        } else if("A192CBC-HS384".equals(algId)) {
            keydataLen = 384;
        } else if("A256CBC-HS512".equals(algId)) {
            keydataLen = 512;
        } else if("A128GCM".equals(algId)) {
            keydataLen = 128;
        } else if("A192GCM".equals(algId)) {
            keydataLen = 192;
        } else if("A256GCM".equals(algId)) {
            keydataLen = 256;
        } else if("ECDH-ES+A128KW".equals(algId)) {
            keydataLen = 128;
        } else if("ECDH-ES+A192KW".equals(algId)) {
            keydataLen = 192;
        } else if("ECDH-ES+A256KW".equals(algId)) {
            keydataLen = 256;
        }
        this.keydataLen = keydataLen;
    }

    ECDHESAlgorithm(String id, String algorithm, ECDSAKeyProvider senderProvider, ECDSAKeyProvider receiverProvider, String partyUInfo, String partyVInfo, String algId, int keydataLen) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, senderProvider, receiverProvider, partyUInfo, partyVInfo, algId, keydataLen);
    }

    @Override
    public byte[] generateAgreementKey() throws KeyAgreementException {
        try {
            return crypto.generateAgreementKey(getDescription(), senderProvider.getPrivateKey(), receiverProvider.getPublicKeyById(null));
        } catch(NoSuchAlgorithmException | InvalidKeyException e) {
            throw new KeyAgreementException(this, e);
        }
    }

    @Override
    public byte[] generateDerivedKey() throws KeyAgreementException {
        try {
            byte[] agreedSecret = generateAgreementKey();
            ConcatKDF concatKDF = ConcatKDF.SHA256ConcatKDF();
            byte[] otherInfo = concatKDF.makeJWEOtherInfo(algId, partyUInfo, partyVInfo, keydataLen, null);
            return concatKDF.getKDFSecret(keydataLen / 8, agreedSecret, otherInfo);
        } catch(KDFException e) {
            throw new KeyAgreementException(this, e);
        }
    }

    @Override
    public Map<String, Object> getPubInfo()  {
        try {
            Map<String, Object> pubInfo = new HashMap<>();
            if(!Utils.isNullOrEmpty(partyUInfo)) {
                pubInfo.put("apu", partyUInfo);
            }
            if(!Utils.isNullOrEmpty(partyVInfo)) {
                pubInfo.put("apv", partyVInfo);
            }
            ECKey pubKey = ECKey.keyBuilder(senderProvider.getPublicKeyById("")).build();
            pubInfo.put("epk", pubKey.toDict());
            return pubInfo;
        } catch(Exception e) {
            return super.getPubInfo();
        }
    }
}
