
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ECKey extends Key{

    private String crv;
    private String x;
    private String y;
    private String d;
    private static Map<String, String> NIST2SEC;
    private static Map<String, String> SEC2NIST;
    final private static Logger logger = LoggerFactory.getLogger(ECKey.class);
    final private static Provider BOUNCYCASTLEPROVIDER = new BouncyCastleProvider();
    final private static org.bouncycastle.jce.spec.ECParameterSpec ECSPEC256 =
        ECNamedCurveTable.getParameterSpec("secp256r1");
    final private static org.bouncycastle.jce.spec.ECParameterSpec ECSPEC384 =
        ECNamedCurveTable.getParameterSpec("secp384r1");
    final private static org.bouncycastle.jce.spec.ECParameterSpec ECSPEP521 =
        ECNamedCurveTable.getParameterSpec("secp521r1");


    private Set<String> longs = new HashSet<String>(Arrays.asList("x", "y", "d"));

    /**
     *
     * Initialize the mappings between the curve representation in
     * Cryptography and the one used by NIST (and in RFC 7518) and vice versa
     *
     * Also initializes know curve parameters
     */
    static {
        NIST2SEC = new HashMap<String, String>();
        NIST2SEC.put("P-256", "secp256r1");
        NIST2SEC.put("P-384", "secp384r1");
        NIST2SEC.put("P-521", "secp521r1");
        SEC2NIST = new HashMap<String, String>();
        SEC2NIST.put("secp256r1", "P-256");
        SEC2NIST.put("secp394r1", "P-384");
        SEC2NIST.put("secp521r1", "P-521");
    }

    public ECKey(String alg, String use, String kid, java.security.Key key, String crv, String x,
                 String y, String d,
                 Map<String,String> args)
        throws HeaderError, JWKException, ValueError, SerializationNotPossible {
        super("EC", alg, use, kid, null, "", "", key, args);
        if(key == null && !NIST2SEC.containsKey(crv)) {
            throw new ValueError("Invalid curve parameter");
        }
        this.crv = Utils.isNullOrEmpty(crv) ? "" : crv;
        this.x = Utils.isNullOrEmpty(x) ? "" : x;
        this.y = Utils.isNullOrEmpty(y) ? "" : y;
        this.d = Utils.isNullOrEmpty(d) ? "" : d;
        members.addAll(Arrays.asList("x", "y", "d", "crv"));
        publicMembers.addAll(Arrays.asList("x", "y", "crv"));
        required.addAll(Arrays.asList("x", "y", "key", "crv"));
        if(this.key != null) {
            loadKey(this.key);
        } else if (!Utils.isNullOrEmpty(this.x) && !Utils.isNullOrEmpty(this.y) &&
            !Utils.isNullOrEmpty(this.crv)) {
            verify();
            deserialize();
        } else
            throw new JWKException("Missing required parameter");
     }

    /**
     * Checks whether this is a private key
     *
     * @return boolean Indicates whether this is private key
     */
    @Override
    public boolean isPrivateKey() {
        if(key != null) {
            return (key instanceof  ECPrivateKey);
        } else {
            return !Utils.isNullOrEmpty(d);
        }
    }

    public void deserialize() throws DeserializationNotPossible {
        try {
            ECParameterSpec ecParameterSpec = getECParameterSpec(crv);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            if(!Utils.isNullOrEmpty(d)) {
                ECPrivateKeySpec ecPrivateKeySpec =
                    new ECPrivateKeySpec(Utils.base64urlToBigInt(d), ecParameterSpec);
                key = keyFactory.generatePrivate(ecPrivateKeySpec);
            } else if(!Utils.isNullOrEmpty(x) && !Utils.isNullOrEmpty(y)) {
                ECPoint publicPoint =
                    new ECPoint(Utils.base64urlToBigInt(x), Utils.base64urlToBigInt(y));
                ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(publicPoint, ecParameterSpec);
                key = keyFactory.generatePublic(ecPublicKeySpec);
            }

        } catch(ValueError | GeneralSecurityException e) {
            throw new DeserializationNotPossible(e.toString());
        }
     }

    @Override
    public java.security.Key getKey(Boolean isPrivate) throws ValueError {
        if(key == null) {
            try {
                deserialize();
            } catch (DeserializationNotPossible e) {
                throw new ValueError(e.toString());
            }
        }
        if(isPrivate) {
            if(!isPrivateKey()) {
                throw new ValueError("Not a private key");
            }
        } else {
            if(isPrivateKey()) {
                try {
                    return (java.security.Key) getPublicKeyFromPrivateKey((ECPrivateKey) key);
                } catch(Exception e) {
                    throw new ValueError(e.toString());
                }
            }
        }
        return key;
    }

    @Override
    /**
     * Go from a ECPrivateKey or ECPublicKey instance to a JWK representation.
     *
     * @param isPrivate
     * @return
     * @throws SerializationNotPossible
     */
    public Map<String, Object> serialize(boolean isPrivate) throws SerializationNotPossible {
        if(Utils.isNullOrEmpty(crv)) {
            throw new SerializationNotPossible();
        }
        Map<String, Object> serializedObject = common();
        serializeECKey(key);
        serializedObject.put("crv", crv);
        serializedObject.put("x", x);
        serializedObject.put("y", y);
        if(isPrivate && Utils.isNullOrEmpty(d)) {
            throw new SerializationNotPossible();
        } else {
            serializedObject.put("d", d);
        }
        return serializedObject;
    }


    private void serializeECKey(java.security.Key key) throws SerializationNotPossible {

        if(key != null) {
            if(key instanceof  ECPrivateKey) {
                ECPrivateKey privateKey = (ECPrivateKey) key;
                d = Utils.bigIntToBase64url(privateKey.getS());
                try {
                    ECPublicKey ecPublicKey = getPublicKeyFromPrivateKey(privateKey);
                    x = Utils.bigIntToBase64url(ecPublicKey.getW().getAffineX());
                    y = Utils.bigIntToBase64url(ecPublicKey.getW().getAffineY());
                }
                catch (Exception e) {
                    throw  new SerializationNotPossible();
                }
            } else if(key instanceof  ECPublicKey) {
                ECPublicKey ecPublicKey = (ECPublicKey) key;
                x = Utils.bigIntToBase64url(ecPublicKey.getW().getAffineX());
                y = Utils.bigIntToBase64url(ecPublicKey.getW().getAffineY());
            } else {
                throw new SerializationNotPossible();
            }
            org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec =
                EC5Util.convertSpec(((ECPrivateKey) key).getParams(), false);
            if(ecParameterSpec.equals(ECSPEC256)) {
                crv = "P-256";
            } else if(ecParameterSpec.equals(ECSPEC384)) {
                crv = "P-384";
            } else if(ecParameterSpec.equals(ECSPEP521)) {
                crv = "P-521";
            } else {
                throw new SerializationNotPossible();
            }
        }
    }

    public void loadKey(java.security.Key key) throws SerializationNotPossible  {
        serializeECKey(key);
        this.key = key;
    }

//
//    public List<Object> getDecryptionKey() {
//        return this.getKey(true);
//    }
//
//    public List<Object> getEncryptionKey(boolean isPrivate) {
//        return this.getKey(isPrivate);
//    }

    public String getCrv() {
        return crv;
    }

    public String getX() {
        return x;
    }

    public String getY() {
        return y;
    }

    public String getD() {
        return d;
    }

    public static Logger getLogger() {
        return logger;
    }

    private ECParameterSpec getECParameterSpec(String curve)
        throws ValueError, java.security.GeneralSecurityException {
        AlgorithmParameters parameters =
            AlgorithmParameters.getInstance("EC", "SunEC");
        if("P-256".equals(curve)) {
            parameters.init(new ECGenParameterSpec("secp256r1"));
        } else if ("P-384".equals(curve)) {
            parameters.init(new ECGenParameterSpec("secp384r1"));
        } else if ("P-521".equals(curve)) {
            parameters.init(new ECGenParameterSpec("secp521r1"));
        } else
            throw new ValueError("Invalid curve");
        return  parameters.getParameterSpec(ECParameterSpec.class);
    }

    private ECPublicKey getPublicKeyFromPrivateKey(ECPrivateKey ecPrivateKey) throws Exception{
        ECPublicKey ecPublicKey = null;
        if(ecPrivateKey != null) {
            JCEECPrivateKey jceecPrivateKey = new JCEECPrivateKey(ecPrivateKey);
            org.bouncycastle.jce.spec.ECParameterSpec ecParameterSpec =
                jceecPrivateKey.getParameters();
            org.bouncycastle.math.ec.ECPoint Q =
                ecParameterSpec.getG().multiply(jceecPrivateKey.getD());
            byte[] publicDerBytes = Q.getEncoded(false);
            org.bouncycastle.math.ec.ECPoint point =
                ecParameterSpec.getCurve().decodePoint(publicDerBytes);
            org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec =
                new org.bouncycastle.jce.spec.ECPublicKeySpec(point, ecParameterSpec);
            KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", BOUNCYCASTLEPROVIDER);
            ecPublicKey = (ECPublicKey) keyFactory.generatePublic(pubSpec);
        }
        return ecPublicKey;
    }

    private boolean isValidCurve(String curve) {
        return NIST2SEC.containsKey(curve);
    }

    public static KeyPair generateECKeyPair(String curve) {
        if(Utils.isNullOrEmpty(curve)) {
            return null;
        }
        if(!NIST2SEC.containsKey(curve)) {
            return null;
        } else  {
            curve = NIST2SEC.get(curve);
        }
        KeyPair keyPair = null;
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curve);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(ecGenSpec, new SecureRandom());
            return keyPairGenerator.generateKeyPair();
        } catch(InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
        }
        return null;
    }

}

