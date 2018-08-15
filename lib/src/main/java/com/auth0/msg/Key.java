package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.DeserializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Abstract JSON Web key class. Jason Web keys are described in
 * RFC 7517 (https://tools.ietf.org/html/rfc7517).
 * The name of parameters used in this class are the same as
 * specified in RFC 7518 (https://tools.ietf.org/html/rfc7518).
 */
public abstract class Key {

    final private static Logger logger = LoggerFactory.getLogger(Key.class);
    protected String kty;
    protected String alg;
    protected String use;
    protected String kid;
    protected String[] x5c;
    protected String x5t;
    protected String x5u;
    protected java.security.Key key;
    protected long inactiveSince;
    protected Map<String, String> args;
    protected Set<String> longs = new HashSet<String>();
    protected Set<String> members = new HashSet<String>
        (Arrays.asList("kty", "alg", "use", "kid", "x5c", "x5t", "x5u"));
    protected Set<String> publicMembers = new HashSet<String>
        (Arrays.asList("kty", "alg", "use", "kid", "x5c", "x5t", "x5u"));
    protected Set<String> required = new HashSet<String>(Arrays.asList("kty"));

    /**
     * Constructs a new Key
     *
     * @param kty Key type (RSA, EC, OCT)
     * @param alg algorithm that this Key is used for
     * @param use The intended use of this Key ("sig" or "enc")
     * @param kid key ID
     * @param x5c array of certificates. The certificate with the key must be first.
     * @param x5t base64url-encoded SHA-1 thumbprint of the DER encoding of an X.509 certificate
     * @param x5u URI that points to a resource for an X.509 public key certificate or chain
     * @param key A java.security.Key that backs this object
     * @param args map of additional parameters for this Key
     */
    public Key(String kty, String alg, String use, String kid, String[] x5c, String x5t,
               String x5u, java.security.Key key, Map<String, String> args) {
        this.kty = Utils.isNullOrEmpty(kty) ? "" : kty;
        this.alg = Utils.isNullOrEmpty(alg) ? "" : alg;
        this.use = Utils.isNullOrEmpty(use) ? "" : use;
        this.kid = Utils.isNullOrEmpty(kid) ? "" : kid;
        if(x5c != null)
            this.x5c = x5c;
        else
            this.x5c = new String[0];
        this.x5t = Utils.isNullOrEmpty(x5t) ? "" : x5t;
        this.x5u = Utils.isNullOrEmpty(x5u) ? "" : x5u;
        this.inactiveSince = 0;
        this.key = key;
        if(args != null)
            this.args = args;
        else
            this.args = new HashMap<>();
    }

    /**
     * Constructs a new Key with all paramets set to empty string or null
     */
    public Key() {
        this("", "", "", "", null, "", "", null, null);
    }

    /**
     * Gets the X.509 certificate chain
     * @return array of X.509 certificates
     */
    public String[] getX5c() {
        return x5c;
    }

    /**
     * Sets the X.509 certificate chain
     * @param x5c array of X.509 certificates
     */
    public void setX5c(String[] x5c) {
        if(x5c == null)
            this.x5c = new String[0];
        else
            this.x5c = x5c;
    }

    /**
     * Gets the base64url-encoded SHA-1 thumbprint of the DER encoding of this Key's X.509
     * certificate
     * @return base64url-encoded SHA-1 thumbprint
     */
    public String getX5t() {
        return x5t;
    }

    /**
     * Sets the SHA-1 thumbprint of the DER encoding of this Key's X.509
     * @param x5t base64url encoded SHA-1 thumbprint
     */
    public void setX5t(String x5t) {
        this.x5t = Utils.isNullOrEmpty(x5t) ? "" : x5t;
    }

    /**
     * Gets the URI resource that represents this Keys certificate chain
     * @return string URI
     */
    public String getX5u() {
        return x5u;
    }

    /**
     * Sets the URI resource that represents this Keys certificate chain
     * @param x5u string URI
     */
    public void setX5u(String x5u) {
        this.x5u = Utils.isNullOrEmpty(x5u) ? "" : x5u;
    }

    /**
     * Gets the key type for this Key
     * @return key type string (RSA, EC, OCT)
     */
    public String getKty() {
        return kty;
    }

    /**
     * Sets the key type for this Key
     * @param kty key type (RSA, EC, OCT)
     */
    public void setKty(String kty) {
        this.kty = Utils.isNullOrEmpty(kty) ? "" : kty;
    }

    /**
     * Gets the algorithm that this Key is used for
     * @return algoritihm string
     */
    public String getAlg() {
        return alg;
    }

    /**
     * Sets the algorithm that this Key is used for
     * Algorithms are specified in RFC 7518 (https://tools.ietf.org/html/rfc7518)
     * @param alg agorithm string
     */
    public void setAlg(String alg) {
        this.alg = Utils.isNullOrEmpty(kty) ? "" : alg;
    }

    /**
     * Gets the usage for this Key (enc = encryption, sig = signature)
     * @return usage fo this Key
     */
    public String getUse() {
        return use;
    }

    /**
     * Sets the usage for this Key
     * @param use usage string (enc = encryption, sig = signature)
     */
    public void setUse(String use) {
        this.use = Utils.isNullOrEmpty(use) ? "" :use;
    }

    /**
     * Gets this Key's key ID
     * @return Key ID string
     */
    public String getKid() {
        return kid;
    }

    /**
     * Sets this Key's key ID
     * @param kid Key ID string
     */
    public void setKid(String kid) {
        this.kid = Utils.isNullOrEmpty(kid) ? "" :kid;
    }

    /**
     * Sets the current time in milliseconds as the starting point of inactivity
     */
    public void setInactiveSince() {
        this.inactiveSince = System.currentTimeMillis();
    }

    /**
     * Sets the specified time milliseconds as the starting point of inactivity
     * @param now time in milleseconds
     */
    public void setInactiveSince(long now) {
        this.inactiveSince = now;
    }

    /**
     * Gets the time when this Key started being inactive
     * @return
     */
    public long getInactiveSince() {
        return inactiveSince;
    }

    /**
     *  Gets a dictionary that includes the private information as well as extra arguments.
     *  his method should *not* be used for exporting information about the key.
     * @return a Map of this Key
     */
    public Map<String, Object> toDict() {
        try {
            Map<String, Object> hmap = serialize(true);
            for (String key : args.keySet()) {
                hmap.put(key, args.get(key));
            }
            return hmap;

        } catch (SerializationNotPossible e) {

        }
        return new HashMap<>();
    }

    /**
     * Return the Map of parameters that are common to all types of keys.
     * @return Map of common Key parameters
     */
    public Map<String, Object> common() {
        Map<String, Object> args = new HashMap<>();
        args.put("kty", kty);

        if (!Utils.isNullOrEmpty(use)) {
            args.put("use", use);
        }
        if (!Utils.isNullOrEmpty(kid)) {
            args.put("kid", kid);
        }
        if (!Utils.isNullOrEmpty(alg)) {
            args.put("alg", alg);
        }
        return args;
    }

    /**
     * Gets string representing the dictionary parameters of this Key
     * @return string representing the dictionary parameters of this Key
     */
    public String toString() {
        return this.toDict().toString();
    }

    /**
     * Sets all common parameters(kty, alg, use, kid, x5t,  x5u, x5c) and
     * additonal parameters for this key
     * @param props Map of parameter names and values
     */
    public void setProperties(Map<String, Object> props) {
        for (Map.Entry<String, Object> entry : props.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            if(key.equals("kty")) {
                kty =  Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("alg")) {
                alg = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("use")) {
                use = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("kid")) {
                kid = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("x5t")) {
                x5t = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("x5u")) {
                x5u = Utils.isNullOrEmpty((String) val) ? "" : (String) val;
            } else if(key.equals("x5c")) {
                if(x5c == null)
                    x5c = new String[0];
                else
                    x5c = (String[]) val;
            } else {
                args.put(key, Utils.isNullOrEmpty((String) val) ? "" : (String) val );
            }
        }
    }


    /**
     *
     * Verify that the information gathered from the on-the-wire
     * representation is of the right type.
     * This is supposed to be run before the info is deserialized.
     * @return boolean
     * @throws HeaderError
     */
    public boolean verify() throws HeaderError {
        return true;
    }


    /**
     * Compare 2 Key instances to find out if they represent the same key
     * @param other The other Key Instance
     * @return true/false if Keys are same/different
     */
    public boolean equals(Object other) {
        try {
            Assert.assertTrue(other instanceof Key);
            Key otherKey = (Key) other;
            Assert.assertEquals(this.getKty(), otherKey.kty);
            Assert.assertEquals(this.getAlg(), otherKey.alg);
            Assert.assertEquals(this.getUse(), otherKey.use);
            Assert.assertEquals(this.getKid(), otherKey.kid);
            Assert.assertEquals(this.getX5c(), otherKey.x5c);
            Assert.assertEquals(this.getX5t(), otherKey.x5t);
            Assert.assertEquals(this.getX5u(), otherKey.x5u);
        } catch (AssertionError error) {
            return false;
        }
        return true;

    }

    /**
     * Gets a list of key names of the JWK dictionary that represents this Key
     * @return
     */
    public List<String> getKeys() {
        return new ArrayList<>(this.toDict().keySet());
    }


    /**
     * Create a thumbprint of the key following the outline in
     * https://tools.ietf.org/html/rfc7638
     * @param hashFunction Hash function used to perform the digest
     * @param members members of the key to use; null to use default required key members
     * @return array of bytes of the thumbprint
     * @throws NoSuchAlgorithmException
     * @throws SerializationNotPossible
     */
    public byte[] thumbprint(String hashFunction, List<String> members) throws
            NoSuchAlgorithmException, SerializationNotPossible {
        if(members == null)
            members = Arrays.asList(this.required.toArray(new String[0]));
        String[] membersArray = members == null ? this.required.toArray(new String[0]) :
                members.toArray(new String[0]);
        Arrays.sort(membersArray);
        Map<String, Object> ser = this.serialize();
        StringBuilder sb = new StringBuilder().append('{');
        for (String elem : membersArray) {
            if(ser.containsKey(elem)) {
                // TODO check if ser.get(elem) is non-string e.g. array, Integer etc.
                sb.append(String.format("\"%s\":\"%s\",", elem, ser.get(elem)));
            }
        }
        sb.deleteCharAt(sb.length() -1).append('}');
        MessageDigest md = MessageDigest.getInstance(hashFunction);
        md.update(StringUtils.getBytesUtf8(sb.toString()));
        return md.digest();
    }

    /**
     * Returns the base64url encoded digest of the key following the outline in
     * https://tools.ietf.org/html/rfc7638
     * @param hashFunction digest algorithm to perform digest
     * @return String base64urlencoded string of thumbprint hash
     * @throws NoSuchAlgorithmException
     * @throws SerializationNotPossible
     */
    public String thumbprint(String hashFunction)
        throws NoSuchAlgorithmException, SerializationNotPossible {
        return Base64.encodeBase64URLSafeString(thumbprint(hashFunction, null));
    }

    /**
     * Construct a Key ID using the thumbprint method and add it to the key attributes.
     */
    public void addKid() {
        try {
            this.kid = thumbprint("SHA-256");
        }
        catch(NoSuchAlgorithmException | SerializationNotPossible e) {
        }
    }

    /**
     * Checks whether this is a private key
     * @return boolean Indicates whether this is private key
     */
    abstract public boolean isPrivateKey();


    /**
     * Checks whether this is a public key
     * @return boolean Indicates whether this is public key
     */
    public boolean isPublicKey() {
        return !isPrivateKey();
    }


    /**
     * map key characteristics into attribute values that can be used
     * to create an on-the-wire representation of the key
     * @return Map of object and internal values
     */

    public abstract Map<String, Object> serialize(boolean isPrivate)
        throws SerializationNotPossible;


    /**
     * map key characteristics into attribute values that can be used
     * to create an on-the-wire representation of the public key
     * @return Map of object and internal values of a public key
     */

    public Map<String, Object>  serialize() throws SerializationNotPossible {
        return serialize(false);
    };

    /**
     * Starting with information gathered from the on-the-wire representation
     * initiate an appropriate java.security.Key and store it internally.
     */
    public abstract void deserialize() throws DeserializationNotPossible;


    /**
     * Gets the interal java.security.Key that represents this Key
     * @param isPrivate whether to get the private key or not
     * @return java.security.Key that backs this object
     * @throws ValueError
     */
    public abstract java.security.Key getKey(Boolean isPrivate) throws ValueError;
}

