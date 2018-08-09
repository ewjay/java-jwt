
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
            serializeRSAKey(this.key);
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

    public RSAKey(java.security.Key key, String use) throws JWKException {
        this("", use, "", null, "", "", key, "", "", "",
            "", "", "", "", "", "", null);
    }

    @Override
    /**
     *  Based on a text based representation of an RSA key this method
     *  instantiates a RSAPrivateKey or RSAPublicKey instance
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
                    List<X509Certificate> certChain = new ArrayList<>();
                    for(String cert : x5c) {
                        try {
                            certChain.add(RSAKey.parseX509Certificate(cert));
                        }
                        catch (GeneralSecurityException e) {
                            System.out.println(e.toString());
                        }
                    }
                    if(!Utils.isNullOrEmpty(x5t)) {
                        try {
                            String calculatedX5t = RSAKey.getX5tForCert(x5c[0]);
                            if(!x5t.equals(calculatedX5t)) {
                                throw new DeserializationNotPossible(
                                    "The thumbprint 'x5t' does not match the certificate.");
                            }
                        } catch(GeneralSecurityException e) {
                            throw new DeserializationNotPossible("Unable to calculate x5t");
                        }
                    }
                    if(certChain.size() > 0) {
                        if(key != null) {
                            if(!key.equals(certChain.get(0).getPublicKey())) {
                                throw new DeserializationNotPossible(
                                    "key described by components and key in x5c not equal");
                            }

                        } else {
                            key = certChain.get(0).getPublicKey();
                        }
                        serializeRSAKey(key);
                    }
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
                serializeRSAKey(key);
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
                serializeRSAKey(key);
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

    /**
     * Instantiates a RSAKey from a private/public key
     * @param key
     * @return
     * @throws JWKException
     */
    public static RSAKey loadKey(java.security.Key key) throws JWKException {
         return new RSAKey(key, "");
    }

    /**
     * Loads a RSAKey key from a PEM file
     * @param file filename of private PEM file
     * @return an RSAKey instance
     * @throws Exception
     */
    public static RSAKey load(String file) throws Exception{
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) getPemRSAKey(file);
        return loadKey(key);
    }

    /**
     * Gets the encryption key
     * @return the encryption key, Could be null.
     * @throws DeserializationNotPossible
     */
    public java.security.Key encryptionKey() throws DeserializationNotPossible{
        if(this.key == null)
            deserialize();
        return this.key;
    }


    /**
     * Converts a public/private RSA key into internal components
     * @param key a private or public key
     */
    private void serializeRSAKey(java.security.Key key) {
        if(key != null && key instanceof RSAPrivateCrtKey) {
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

    /**
     * Checks if all private key components are available
     * @return true/false
     */
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

    /**
     * Checks if all public key members are available
     * @return true/false
     */
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

//    private static PrivateKey getPemPrivateKey(String key, String algorithm)
//        throws NoSuchAlgorithmException, InvalidKeySpecException {
//        String privKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----\n", "");
//        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
//        byte [] decoded = Base64.decodeBase64(privKeyPEM);
//        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
//        KeyFactory kf = KeyFactory.getInstance(algorithm);
//        return kf.generatePrivate(spec);
//    }
//
//    private static PublicKey getPemPublicKey(String key, String algorithm)
//        throws NoSuchAlgorithmException, InvalidKeySpecException {
//        String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----\n", "");
//        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
//        byte [] decoded = Base64.decodeBase64(publicKeyPEM);
//        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
//        KeyFactory kf = KeyFactory.getInstance(algorithm);
//        return kf.generatePublic(spec);
//
//    }
//
//    private static byte[] getFileBytes(String filename) throws FileNotFoundException, IOException {
//        File f = new File(filename);
//        FileInputStream fis = new FileInputStream(f);
//        DataInputStream dis = new DataInputStream(fis);
//        byte[] keyBytes = new byte[(int) f.length()];
//        dis.readFully(keyBytes);
//        dis.close();
//        return keyBytes;
//    }

    /**
     * Get the key from PEM encoded file
     * @param filename filename of PEM file
     * @return private or public key
     */
    public static java.security.Key getPemRSAKey(String filename) {
        java.security.Key key = null;
        try {
            key = KeyUtils.readRSAKeyFromFile(filename);
        } catch(IOException e) {
        }
        return key;
    }

    /**
     * Parse an X509 certificate string and return the X509Certificate
     * @param cert X509 Certificate String
     * @return X509Certificate The certificate
     * @throws GeneralSecurityException
     */
     public static X509Certificate parseX509Certificate(String cert)
        throws GeneralSecurityException {
        try {
            String wrappedCert = "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----\n";
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)f.generateCertificate(
                new ByteArrayInputStream(wrappedCert.getBytes("UTF-8")));
            return certificate;
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Gets the base64encoded SHA-1 thumbprint of the X509 certificate string
     * @param certificate X509 certificate
     * @return base64encoded SHA-1 thumbprint
     */
    public static String getX5tForCert(String certificate) throws GeneralSecurityException{
        try {
            byte[] decodedBytes = Base64.decodeBase64(certificate.getBytes("UTF-8"));
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.reset();
            md.update(decodedBytes);
            return new String(Base64.encodeBase64URLSafe(md.digest()), Charset.forName("UTF-8"));
        } catch(UnsupportedEncodingException | NoSuchAlgorithmException e) {
            throw new GeneralSecurityException(e);
        }
    }

    /**
     * Generates a RSA Key pair
     * @param size keysize
     * @return KeyPair
     */
    public static KeyPair generateRSAKeyPair(int size) {
        KeyPair keyPair = null;
        try {
            RSAKeyGenParameterSpec rsaKeyGenParameterSpec = new RSAKeyGenParameterSpec(size, RSAKeyGenParameterSpec.F4);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(rsaKeyGenParameterSpec);
            keyPair =  keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {

        }
        return keyPair;
    }

}

