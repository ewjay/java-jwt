
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.util.*;

public class ECKey extends Key{

    private String crv;
    private String x;
    private String y;
    private String d;
    final private static Logger logger = LoggerFactory.getLogger(ECKey.class);
    private static Set<String> longs = new HashSet<String>(Arrays.asList("x", "y", "d"));

    public ECKey(String alg, String use, String kid, java.security.Key key, String crv, String x,
                 String y, String d,
                 Map<String,String> args) throws HeaderError, JWKException, ValueError {
        super("EC", alg, use, kid, null, "", "", key, args);
        this.crv = crv;
        this.x = x;
        this.y = y;
        this.d = d;
        members.addAll(Arrays.asList("x", "y", "d", "crv"));
        publicMembers.addAll(Arrays.asList("x", "y", "crv"));
        required.addAll(Arrays.asList("x", "y", "key", "crv"));
        if(this.key != null) {
            loadKey(this.key);
        } else if (!Utils.isNullOrEmpty(this.x) && !Utils.isNullOrEmpty(this.y)) {
            verify();
            deserialize();
        } else
            throw new JWKException("Missing required parameter");

        if(!Utils.isNullOrEmpty(this.crv)) {
            try {
                this.verify();
            } catch (HeaderError headerError) {
                headerError.printStackTrace();
            }
            this.deserialize();
        } else if(this.getKey(false) != null ) {
            // TODO check getKey() in original
            this.loadKey(key);
        }
    }

//    public ECKey() {
//        this("", "", "", null, "", null, null, null, null);
//    }

    /**
     * Checks whether this is a private key
     *
     * @return boolean Indicates whether this is private key
     */
    @Override
    public boolean isPrivateKey() {
        return false;
    }

    public void deserialize() {
//        try {
//            if(!(this.x instanceof Number)) {
//                this.x = deser(this.x);
//            }
//            if(!(this.y instanceof Number)) {
//                this.y = deser(this.y);
//            }
//        } catch (ParseException e) {
//            logger.error("Couldn't parse value");
//        }
//
//        this.curve = byName(this.crv);
//        if(this.d != null) {
//            if(this.d instanceof String) {
//                this.d = deser(this.d);
//            }
//        }
        // TODO
    }

    @Override
    public java.security.Key getKey(Boolean isPrivate) throws ValueError {
        return null;
    }

//    private EllipticCurve byName(String name) {
//        if(name.equals("P-256")) {
//            return EllipticCurve();
//        } else if(name.equals("P-384")) {
//            return EllipticCurve();
//        } else if(name.equals("P-521")) {
//            return EllipticCurve();
//        }
//    }
//
//    public List<Object> getKey(boolean isPrivate) {
//        if(isPrivate) {
//            return new ArrayList<>(Arrays.asList(this.d));
//        } else {
//            return new ArrayList<>(Arrays.asList(this.x, this.y));
//        }
//    }

//    public Object serialize(boolean isPrivate) throws SerializationNotPossible {
//        if(this.crv == null && this.curve == null) {
//            throw new SerializationNotPossible();
//        }
//
//        Map<String, String> args = common();
//        args.put("crv", this.curve.getClass().getName());
//        args.put("x", longToBase64(this.x));
//        args.put("y", longToBase64(this.y));
//
//        if(isPrivate && this.d != null) {
//            args.put("d", longToBase64(this.d));
//        }
//
//
//        return args;
//    }


    public Map<String, Object> serialize(boolean isPrivate) throws SerializationNotPossible {
        // TODO
        return null;
    }


    private void serializeECKey(java.security.Key key) {

        if(key != null) {
            if(key instanceof  ECPrivateKey) {
                ECPrivateKey privateKey = (ECPrivateKey) key;
                d = Utils.bigIntToBase64url(privateKey.getS());
                // TODO serialize public key parts (x, y)
//                x = Utils.bigIntToBase64url(privateKey.ge)
            } else if(key instanceof  ECPublicKey) {

            }
        }

        if(key instanceof ECPrivateKey) {

        } else if(key instanceof ECPublicKey) {

        }
//        ECGenParameterSpec genParameterSpec = new ECGenParameterSpec();
    }

    public ECKey loadKey(java.security.Key key) {
        serializeECKey(key);
        this.key = key;
        return this;
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

    public void setCrv(String crv) {
        this.crv = crv;
    }

    public Object getX() {
        return x;
    }

    public void setX(String x) {
        this.x = x;
    }

    public Object getY() {
        return y;
    }

    public void setY(String y) {
        this.y = y;
    }

    public Object getD() {
        return d;
    }

    public void setD(String d) {
        this.d = d;
    }

//    public String getCurve() {
//        return curve;
//    }
//
//    public void setCurve(Object curve) {
//        this.curve = curve;
//    }

    public static Logger getLogger() {
        return logger;
    }

    public static Set<String> getLongs() {
        return longs;
    }

    public static void setLongs(Set<String> longs) {
        ECKey.longs = longs;
    }

//    public static Set<String> getMembers() {
//        return members;
//    }
//
//    public static void setMembers(Set<String> members) {
//        ECKey.members = members;
//    }
//
//    public static Set<String> getPublicMembers() {
//        return publicMembers;
//    }
//
//    public static void setPublicMembers(Set<String> publicMembers) {
//        ECKey.publicMembers = publicMembers;
//    }
//
//    public static Set<String> getRequired() {
//        return required;
//    }
//
//    public static void setRequired(Set<String> required) {
//        ECKey.required = required;
//    }

    private ECParameterSpec getECParameterSpec(String curve) throws ValueError, java.security.GeneralSecurityException {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
        if(curve.equals("P-256")) {
            parameters.init(new ECGenParameterSpec("secp256r1"));
        } else if (curve.equals("P-384")) {
            parameters.init(new ECGenParameterSpec("secp384r1"));
        } else if (curve.equals("P-521")) {
            parameters.init(new ECGenParameterSpec("secp521r1"));
        } else
            throw new ValueError("Invalid curve");
        return  parameters.getParameterSpec(ECParameterSpec.class);
    }

}

