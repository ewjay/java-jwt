
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Map;


public class RSAKey extends Key {

    final private static Logger logger = LoggerFactory.getLogger(RSAKey.class);
    private String n;
    private String e;
    private String d;
    private String p;
    private String q;
    private String dp;
    private String dq;
    private String qi;
    private String oth;

    public RSAKey(String alg, String use, String kid, String[] x5c, String x5t,
                  String x5u, java.security.Key key, String n, String e, String d, String p,
                  String q, String dp, String dq, String qi, String oth, Map<String, String> args)
            throws JWKException{
        super("RSA", alg, use, kid, x5c, x5t, x5u, key, args);
        members.addAll(Arrays.asList("n", "e", "d", "p", "q"));
        longs.addAll(Arrays.asList("n", "e", "d", "p", "q", "dp", "dq", "qi", "oth"));
        publicMembers.addAll(Arrays.asList("n", "e"));
        required.addAll(Arrays.asList("n", "e"));
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.dp = dp;
        this.dq = dq;
        this.qi = qi;
        this.oth = oth; // TODO should be an array of oths

        boolean hasPublicKeyParts = (!Utils.isNullOrEmpty(n))  &&
                (!Utils.isNullOrEmpty(n));
        boolean hasX509CertChain = this.x5c != null && this.x5c.length > 0;

        if (this.key != null ) {
            _serializeRSAKey(this.key);
        } else if (hasPublicKeyParts) {
            deserialize();
        } else if (hasX509CertChain) {
            deserialize();
        }else if (this.n == null && this.e == null) {

        } else
            throw new JWKException("Missing required parameter");
    }

    public RSAKey(String use) throws JWKException {
        this("", use, "", null, "", "", null, "", "",
            "", "", "", "", "", "", "", null);
    }

    public RSAKey(java.security.Key key) throws JWKException {
        this("", "", "", null, "", "", key, "", "", "",
            "", "", "", "", "", "", null);
    }

    @Override
    /**
     *  Based on a text based representation of an RSA key this method
     *  instantiates a
     *  RSAPrivateKey or
     *  RSAPublicKey instance
     */
    public void deserialize() throws DeserializationNotPossible {

        try {
            if(key == null) {
                if(isPrivateKey()) {
                    BigInteger n = Utils.base64urlToBigInt(this.n);
                    BigInteger e = Utils.base64urlToBigInt(this.e);
                    BigInteger d = Utils.base64urlToBigInt(this.d);
                    BigInteger p = Utils.base64urlToBigInt(this.p);
                    BigInteger q = Utils.base64urlToBigInt(this.q);
                    BigInteger dp = Utils.base64urlToBigInt(this.dp);
                    BigInteger dq = Utils.base64urlToBigInt(this.dq);
                    BigInteger qi = Utils.base64urlToBigInt(this.qi);

                    RSAPrivateCrtKeySpec privSpec =
                        new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    this.key = factory.generatePrivate(privSpec);

                } else if(checkPublicKeyMembers()) {
                    BigInteger n = Utils.base64urlToBigInt(this.n);
                    BigInteger e = Utils.base64urlToBigInt(this.e);
                    RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(n, e);
                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    this.key = factory.generatePublic(pubSpec);
                }

                if(x5c != null && x5c.length > 0) {
                    // TODO handle certs
                }
            }
            if(key == null)
                throw new DeserializationNotPossible("");
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new DeserializationNotPossible(e.toString());
        }
    }

    @Override
     /**
     * Given a RSAPrivateKey or
     * RSAPublicKey instance construct the JWK representation.
     * param private: Should I do the private part or not
     * return: A JWK as a dictionary
     * @param isPrivate whether to get private key part
     * @return a JWK as as dictionary
     * @throws SerializationNotPossible
     */
     public Map<String,Object> serialize(boolean isPrivate) throws SerializationNotPossible {
        if(key == null) {
            throw new SerializationNotPossible();
        }
        Map<String, Object> args = common();
        if(isPrivate) {
            if(!checkPrivateKeyMembers()) {
                _serializeRSAKey(key);
            }
            if(!checkPrivateKeyMembers())
                throw new SerializationNotPossible();
            args.put("n", n);
            args.put("e", e);
            args.put("d", d);
            args.put("p", p);
            args.put("q", q);
            args.put("dp", dp);
            args.put("dq", dq);
            args.put("qi", qi);

        } else {
            if(!checkPublicKeyMembers())
                _serializeRSAKey(key);
            if(!checkPublicKeyMembers())
                throw new SerializationNotPossible();
            args.put("n", n);
            args.put("e", e);
        }

        if(x5c != null && x5c.length > 0) {
            args. put("x5c", x5c);
        }
        return args;
    }

    public static RSAKey loadKey(java.security.Key key) throws JWKException {
         return new RSAKey(key);
    }

    public static RSAKey load(String file) throws Exception{
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) getPemPrivateKey(file, "RSA");
        return loadKey(key);
    }

    public java.security.Key encryptionKey() throws DeserializationNotPossible{
        if(this.key == null)
            deserialize();
        return this.key;
    }


    private void _serializeRSAKey(java.security.Key key) {
        if(key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key;
            n = Utils.bigIntToBase64url(privateKey.getModulus());
            e = Utils.bigIntToBase64url(privateKey.getPublicExponent());
            d = Utils.bigIntToBase64url(privateKey.getPrivateExponent());
            p = Utils.bigIntToBase64url(privateKey.getPrimeP());
            q = Utils.bigIntToBase64url(privateKey.getPrimeQ());
            dp = Utils.bigIntToBase64url(privateKey.getPrimeExponentP());
            dq = Utils.bigIntToBase64url(privateKey.getPrimeExponentQ());

        } else if(key instanceof RSAPublicKey) {
            RSAPublicKey publicKey = (RSAPublicKey) key;
            n = Utils.bigIntToBase64url(publicKey.getModulus());
            e = Utils.bigIntToBase64url(publicKey.getPublicExponent());
        }
    }

    @Override
    public boolean isPrivateKey() {

        if(key != null) {
            if(key instanceof RSAPrivateKey)
                return true;
        } else {
            if( checkPrivateKeyMembers()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkPrivateKeyMembers() {
         return (!Utils.isNullOrEmpty(n) &&
                 !Utils.isNullOrEmpty(e) &&
                 !Utils.isNullOrEmpty(d) &&
                 !Utils.isNullOrEmpty(p) &&
                 !Utils.isNullOrEmpty(q) &&
                 !Utils.isNullOrEmpty(dp) &&
                 !Utils.isNullOrEmpty(dq) &&
                 !Utils.isNullOrEmpty(qi));
     }

    private boolean checkPublicKeyMembers() {
        return (!Utils.isNullOrEmpty(n) && !Utils.isNullOrEmpty(e));
    }

    @Override
    public void setProperties(Map<String, Object> props) {
         for (Map.Entry<String, Object> entry : props.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if(key.equals("n")) {
                n = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("e")) {
                e = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("p")) {
                p = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("q")) {
                q = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("dp")) {
                dp = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("dq")) {
                dq = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            }  else if(key.equals("qi")) {
                qi = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            }  else if(key.equals("oth")) {
                oth = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else {
                super.setProperties(props);
            }
        }
    }

    @Override
    /**
     *
     */
    public java.security.Key getKey(Boolean isPrivate) throws ValueError {
        try {
            if(key == null) {
                deserialize();
            }
            if(!isPrivate && isPrivateKey()) {
                if(key instanceof RSAPrivateCrtKey) {
                    RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) key;
                    BigInteger n = privateKey.getModulus();
                    BigInteger e = privateKey.getPublicExponent();
                    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    return keyFactory.generatePublic(publicKeySpec);
                }
            }
            if(isPrivate && !isPrivateKey())
                throw new ValueError("Not a private key");
            return key;
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException | DeserializationNotPossible e) {
            throw new ValueError(e.toString());
        }
    }

    private static PrivateKey getPemPrivateKey(String key, String algorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----\n", "");
        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
        byte [] decoded = Base64.decodeBase64(privKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePrivate(spec);
    }

    private static PublicKey getPemPublicKey(String key, String algorithm)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        byte [] decoded = Base64.decodeBase64(publicKeyPEM);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(spec);

    }

    private static byte[] getFileBytes(String filename) throws FileNotFoundException, IOException {
        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();
        return keyBytes;
    }

    public static java.security.Key getPemRSAKey(String filename)
        throws FileNotFoundException, IOException, UnknownKeyType {
        java.security.Key rsaKey = null;
        try {
            byte[] keyBytes = RSAKey.getFileBytes(filename);
            String temp = new String(keyBytes);
            if(temp.indexOf("-----BEGIN PUBLIC KEY-----\n") >= 0) {
                rsaKey = getPemPublicKey(temp, "RSA");

            } else if(temp.indexOf("-----BEGIN PRIVATE KEY-----\n") >= 0) {
                rsaKey = getPemPrivateKey(temp, "RSA");
            } else {
                throw new UnknownKeyType("Unknown RSA key format");
            }
        } catch(InvalidKeySpecException e) {

        } catch(NoSuchAlgorithmException e) {

        }
        return rsaKey;
    }



}

