
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;

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
import java.security.PrivateKey;
import java.security.PublicKey;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;


public class RSAKey extends Key {

    private String n;
    private String e;
    private String d;
    private String p;
    private String q;
    private String dp;
    private String dq;
    private String qi;
    private List<Map<String, String>> oth;


    /**
     * Constructs a new RSAKey instance
     * Can just pass the private/public base64url encoded string components of the JWK
     * or the java.security.interface.RSAKey
     *
     * The name of parameters used in this class are the same as
     * specified in the RFC 7517.

     * According to RFC7517 the JWK representation of a RSA (public key) can be
     * something like this:
     *
     * {
     *  "kty":"RSA",
     *  "use":"sig",
     *  "kid":"1b94c",
     *  "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08
     *  PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Q
     *  u2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4a
     *  YWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwH
     *  MTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMv
     *  VfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
     *  "e":"AQAB",
     * }
     *
     * Parameters according to https://tools.ietf.org/html/rfc7518#section-6.3
     *
     * @param alg algorithm that this Key is used for
     * @param use The intended use of this Key ("sig" or "enc")
     * @param kid kid key ID
     * @param x5c array of certificates. The certificate with the key must be first.
     * @param x5t base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate
     * @param x5u URI that points to a resource for an X.509 public key certificate or chain
     * @param key the java.security.interface.RSAKey that backs this object
     * @param n base64url encoded modulus value for the RSA public key
     * @param e base64url encoded exponent value for the RSA public key
     * @param d base64url encoded private exponent value for the RSA private key
     * @param p base64url encoded first prime factor value for the RSA private key
     * @param q base64url encoded second Prime Factor value for the RSA private key
     * @param dp base64url encoded First Factor CRT Exponent value for the RSA private key
     * @param dq base64url encoded Second Factor CRT Exponent value for the RSA private key
     * @param qi base64url encoded First CRT Coefficient value for the RSA private key
     * @param oth list of base64url encoded Other Primes Info encoded  value for the RSA private key
     * @param args dictionary of additional information for this key
     * @throws JWKException
     */
    public RSAKey(String alg, String use, String kid, String[] x5c, String x5t,
                  String x5u, java.security.Key key, String n, String e, String d, String p,
                  String q, String dp, String dq, String qi, List<Map<String,String>> oth,
                  Map<String, String> args) throws JWKException{
        super("RSA", alg, use, kid, x5c, x5t, x5u, key, args);
        members.addAll(Arrays.asList("n", "e", "d", "p", "q"));
        longs.addAll(Arrays.asList("n", "e", "d", "p", "q", "dp", "dq", "qi", "oth"));
        publicMembers.addAll(Arrays.asList("n", "e"));
        required.addAll(Arrays.asList("n", "e"));
        this.n = Utils.isNullOrEmpty(n) ? "" : n;
        this.e = Utils.isNullOrEmpty(e) ? "" : e;
        this.d = Utils.isNullOrEmpty(d) ? "" : d;
        this.p = Utils.isNullOrEmpty(p) ? "" : p;
        this.q = Utils.isNullOrEmpty(q) ? "" : q;
        this.dp = Utils.isNullOrEmpty(dp) ? "" : dp;
        this.dq = Utils.isNullOrEmpty(dq) ? "" : dq;
        this.qi = Utils.isNullOrEmpty(qi) ? "" : qi;
        this.oth = oth == null? Collections.<Map<String,String>>emptyList() : oth;

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


    /**
     * Constructs a RSAKey instance using only a java.security.interfaces.RSAKey key
     * @param key java.security.interfaces.RSAKey(private/public) instance
     * @param use use string (enc/sig)
     * @throws JWKException
     */
    public RSAKey(java.security.Key key, String use) throws JWKException {
        this("", use, "", null, "", "", key, "", "", "",
            "", "", "", "", "", Collections.<Map<String,String>>emptyList(), null);
    }

    /**
     * Convenience method to get a RSAKey builder
     * @return new RSAKeyBuilder instance
     */
    public static RSAKeyBuilder builder() {
        return new RSAKeyBuilder();
    }

    /**
     * Convenience method to get a RSAKey builder with a java.security.Key (private/public RSA key)
     * @param key java
     * @return instance of RSAKeyBuilder
     */
    public static RSAKeyBuilder keyBuilder(java.security.Key key) {
        return new RSAKeyBuilder(key);
    }

    /**
     * Convenience method to get a RSAKey builder using the RSA public key components
     * @param n base64url encoded modulus value for the RSA public key
     * @param e base64url encoded exponent value for the RSA public key
     * @return instance of RSAKeyBuilder
     */
    public static RSAKeyBuilder publicKeyBuilder(String n, String e) {
        return new RSAKeyBuilder(n, e);
    }

    /**
     * Get a RSAKey builder using the RSA private key components
     * @param n base64url encoded modulus value for the RSA public key
     * @param e base64url encoded exponent value for the RSA public key
     * @param d base64url encoded private exponent value for the RSA private key
     * @param p base64url encoded first prime factor value for the RSA private key
     * @param q base64url encoded second Prime Factor value for the RSA private key
     * @param dp base64url encoded First Factor CRT Exponent value for the RSA private key
     * @param dq base64url encoded Second Factor CRT Exponent value for the RSA private key
     * @param qi base64url encoded First CRT Coefficient value for the RSA private key
     * @param oth list of base64url encoded Other Primes Info encoded  value for the RSA private key
     * @return instance of RSAKeyBuilder
     */
    public static RSAKeyBuilder privateKeyBuilder(String n, String e, String d, String p, String q,
        String dp, String dq, String qi, List<Map<String, String>> oth) {
        return new RSAKeyBuilder(n, e, d, p, q, dp, dq, qi, oth);
    }

    /**
     * Builder for RSAKey class
     */
    public static class RSAKeyBuilder extends KeyBuilder<RSAKeyBuilder> {
        private String n;
        private String e;
        private String d;
        private String p;
        private String q;
        private String dp;
        private String dq;
        private String qi;
        private List<Map<String, String>> oth;


        @Override
        public RSAKeyBuilder self() {
            return this;
        }

        /**
         * Create a RSAKey builder
         */
        public RSAKeyBuilder() {
        }

        /**
         * Create a RSAKey builder using a java.security.Key
         * @param key private/public java.security.Key RSA key instance
         */
        public RSAKeyBuilder(java.security.Key key) {
            this.key = key;
        }

        /**
         * Create a RSAKey builder using the RSA public key components
         * @param n base64url encoded modulus value for the RSA public key
         * @param e base64url encoded exponent value for the RSA public key
         */
        public RSAKeyBuilder(String n, String e) {
            this.n = n;
            this.e = e;
        }

        /**
         * Create a RSAKey builder using the RSA private key comonents
         * @param n base64url encoded modulus value for the RSA public key
         * @param e base64url encoded exponent value for the RSA public key
         * @param d base64url encoded private exponent value for the RSA private key
         * @param p base64url encoded first prime factor value for the RSA private key
         * @param q base64url encoded second Prime Factor value for the RSA private key
         * @param dp base64url encoded First Factor CRT Exponent value for the RSA private key
         * @param dq base64url encoded Second Factor CRT Exponent value for the RSA private key
         * @param qi base64url encoded First CRT Coefficient value for the RSA private key
         * @param oth list of base64url encoded Other Primes Info encoded  value for the RSA private key
         */
        public RSAKeyBuilder(String n, String e, String d, String p, String q, String dp, String dq,
                             String qi, List<Map<String, String>> oth) {

            this.n = n;
            this.e = e;
            this.d = d;
            this.p = p;
            this.q = q;
            this.dp = dp;
            this.dq = dq;
            this.qi = qi;
            this.oth = oth;
        }

        /**
         * Set the modulus of the public key component
         * @param n base64url encoded modulus value for the RSA public key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setN(String n) {
            this.n = n;
            return this;
        }

        /**
         * Set the exponent of the public key component
         * @param e base64url encoded exponent value for the RSA public key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setE(String e) {
            this.e = e;
            return this;
        }

        /**
         * Set the private exponent of the private key compoent
         * @param d base64url encoded private exponent value for the RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setD(String d) {
            this.d = d;
            return this;
        }

        /**
         * Set the first prime factor of the private key compoent
         * @param p base64url encoded first prime factor value for the RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setP(String p) {
            this.p = p;
            return this;
        }

        /**
         * Set second Prime Factor the of the private key compoent
         * @param q base64url encoded second Prime Factor value for the RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setQ(String q) {
            this.q = q;
            return this;
        }

        /**
         * Set the First Factor CRT Exponent of the private key compoent
         * @param dp base64url encoded First Factor CRT Exponent value for the RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setDp(String dp) {
            this.dp = dp;
            return this;
        }

        /**
         * Set the Second Factor CRT Exponent of the private key compoent
         * @param dq base64url encoded Second Factor CRT Exponent value for the RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setDq(String dq) {
            this.dq = dq;
            return this;
        }

        /**
         * Set the of irst CRT Coefficient the private key compoent
         * @param qi base64url encoded First CRT Coefficient value for the RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setQi(String qi) {
            this.qi = qi;
            return this;
        }

        /**
         * Set the Other Primes Info of the private key compoent
         * @param oth list of base64url encoded Other Primes Info encoded  value for the
         *            RSA private key
         * @return RSAKeyBuilder instance
         */
        public RSAKeyBuilder setOth(List<Map<String, String>> oth) {
            this.oth = oth;
            return this;
        }

        /**
         * Create a new RSAKey instance using the builder's values
         * @return newly created RSAKey instance
         * @throws JWKException
         */
        public RSAKey build() throws JWKException{
            return new
                RSAKey(alg, use, kid, x5c, x5t, x5u, key, n, e, d, p, q, dp, dq, qi, oth, args);
        }
    }

    @Override
    /**
     *  Based on a text based representation of an RSA key this method
     *  instantiates a RSAPrivateKey or RSAPublicKey internally
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
                    List<X509Certificate> certChain = new ArrayList<>();
                    for(String cert : x5c) {
                        try {
                            certChain.add(RSAKey.parseX509Certificate(cert));
                        }
                        catch (GeneralSecurityException e) {
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
     * Serializes the internal RSAPrivateKey or RSAPublicKey key into a JWK representation.
     *
     * @param isPrivate whether to get private key part
     * @return a JWK as a dictionary
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
     * Instantiates a RSAKey from a java.security.interfaces.RSAKey(private/public) key
     * @param key
     * @return A RSAKey instance
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
     * Converts a java.security.interfaces.RSAKey(public/private) RSA key into internal components
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
            qi = Utils.bigIntToBase64url(privateKey.getCrtCoefficient());

        } else if(key instanceof RSAPublicKey) {
            RSAPublicKey publicKey = (RSAPublicKey) key;
            n = Utils.bigIntToBase64url(publicKey.getModulus());
            e = Utils.bigIntToBase64url(publicKey.getPublicExponent());
        }
    }

    @Override
    public boolean isPrivateKey() {
        if(key != null) {
            return (key instanceof RSAPrivateKey);
        } else {
            return checkPrivateKeyMembers();
        }
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
    /**
     * Sets properties for the JWK private/public key components
     */
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
                oth = val == null ? Collections.<Map<String,String>>emptyList() :
                    (List<Map<String, String>>) val;
            } else {
                super.setProperties(props);
            }
        }
    }

    @Override
    /**
     * Gets the java.security.interfaces.RSAKey (Private/public) key
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

    /**
     * Get the key from PEM encoded file
     * @param filename filename of PEM encoded key file
     * @return private or public key
     * @throws IOException
     */
    public static java.security.Key getPemRSAKey(String filename) throws IOException{
        return KeyUtils.getRSAKeyFromFile(filename);
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
            final String certHeader = "-----BEGIN CERTIFICATE-----\n";
            final String certFooter = "\n-----END CERTIFICATE-----\n";
            String wrappedCert = cert;
            if(!cert.startsWith(certHeader)) {
                wrappedCert = certHeader + cert + certFooter;
            }
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
     * @param size keysize of the RSA key
     * @return KeyPair containing private/public keys
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

    /**
     * Gets the base64url encoded Modulus of the public key
     * @return base64url encoded Modulus of the public key
     */
    public String getN() {
        return n;
    }


    /**
     * Gets the base64url encoded Exponent of the public key
     * @return base64url encoded Exponent of the public key
     */
    public String getE() {
        return e;
    }

    /**
     * Gets the base64url encoded Private Exponent of the private key
     * @return base64url encoded of Private Exponent the private key
     */
    public String getD() {
        return d;
    }

    /**
     * Gets the base64url encoded  of First Prime Factor the private key
     * @return base64url encoded of the First Prime Factor private key
     */
    public String getP() {
        return p;
    }

    /**
     * Gets the base64url encoded Second Prime Factor of the private key
     * @return base64url encoded of Second Prime Factor the private key
     */
    public String getQ() {
        return q;
    }

    /**
     * Gets the base64url encoded First Factor CRT Exponent of the private key
     * @return base64url encoded First Factor CRT Exponent of the private key
     */
    public String getDp() {
        return dp;
    }

    /**
     * Gets the base64url encoded Second Factor CRT Exponent of the private key
     * @return base64url encoded Second Factor CRT Exponent of the private key
     */
    public String getDq() {
        return dq;
    }

    /**
     * Gets the base64url encoded First CRT Coefficient of the private key
     * @return base64url encoded First CRT Coefficient of the private key
     */
    public String getQi() {
        return qi;
    }

    /**
     * Gets list of the base64url encoded Other Primes Info of the private key
     * @return list of base64url encoded Other Primes Info of the  private key
     */
    public List<Map<String, String>> getOth() {
        return oth;
    }

    @Override
    public boolean equals(Object other) {

        try {
            if (other instanceof RSAKey) {
                RSAKey rsaOther = (RSAKey) other;
                if (key == null) {
                    deserialize();
                }
                if(rsaOther.key == null) {
                    rsaOther.deserialize();
                }
                if(key instanceof PrivateKey && rsaOther.key instanceof PrivateKey) {
                    if(checkPrivateKeyMembers() && rsaOther.checkPrivateKeyMembers()) {
                        if(e.equals(rsaOther.e) &&
                            n.equals(rsaOther.n) &&
                            d.equals(rsaOther.d) &&
                            p.equals(rsaOther.p) &&
                            q.equals(rsaOther.q) &&
                            dp.equals(rsaOther.dp) &&
                            dq.equals(rsaOther.dq) &&
                            qi.equals(rsaOther.qi) &&
                            oth.equals(rsaOther.oth)) {
                            return true;
                        }
                    }

                } else if (key instanceof PublicKey && rsaOther.key instanceof PublicKey) {
                    if(checkPublicKeyMembers() && rsaOther.checkPublicKeyMembers()) {
                        if(e.equals(rsaOther.e) && n.equals(rsaOther.n)) {
                            return true;
                        }
                    }
                }

            }
        } catch (DeserializationNotPossible e) {

        }
        return false;
    }
}

