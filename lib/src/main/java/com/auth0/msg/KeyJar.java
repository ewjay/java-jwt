
package com.auth0.msg;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.KeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Class for organizing KeyBundles for a list of issuers( or owners)
 */
public class KeyJar {

    private boolean verifySSL;

    private long removeAfter;
    private Map<String,List<KeyBundle>> issuerKeys;
    final private static org.slf4j.Logger logger = LoggerFactory.getLogger(KeyJar.class);

    /**
     * Constructs a KeyJar
     *
     * @param verifySSL whether to verify SSL connections
     * @param removeAfter time in milliseconds to remove outdated KeyBundles
     */
    public KeyJar(boolean verifySSL, long removeAfter) {
        this.verifySSL = verifySSL;
        this.removeAfter = removeAfter;
        issuerKeys = new HashMap<String, List<KeyBundle>>();
    }

    /**
     * Constructs a new KeyJar
     */
    public KeyJar() {
        this(true, 3600000);
    }

    /**
     * Add a set of keys by url. This method will create a
     * KeyBundle instance with the url as source specification. If no fileformat is given it's assumed
     * that what's on the other side is a JWKS.
     * @param owner string of who issued the keys
     * @param url URL string wherer the key be found
     * @param args extra parameters for instantiating KeyBundle
     * @return a KeyBundle instance
     * @throws KeyException
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle addUrl(String owner, String url, Map<String,String> args)
        throws KeyException, ImportException, IOException, JWKException, ValueError {
        if(url == null || url.isEmpty()) {
            throw new KeyException("No jwksUri");
        }
        KeyBundle keyBundle = new KeyBundle(url, "jwk", null);
        addKeyBundle(owner, keyBundle);
        return keyBundle;
    }

    /**
     * Add Symmetric Key to Jar using
     * @param owner owner of the key
     * @param k symmetric key bytes
     * @param usage List of what the key can be used for signing/signature verification (sig)
     *              and/or encryption/decryption (enc)
     * @throws ImportException
     */
    public void addSymmetricKey(String owner, byte[] k, List<String> usage)
        throws ImportException, IOException, JWKException, ValueError {
        if(!issuerKeys.containsKey(owner)) {
            issuerKeys.put(owner, new ArrayList<KeyBundle>());
        }
        String b64Key = Base64.encodeBase64URLSafeString(k);
        if(usage == null || usage.isEmpty()) {
            HashMap<String, Object> jwk = new HashMap<String, Object>();
            jwk.put("kty", "oct");
            jwk.put("k", b64Key);
            ArrayList<Map<String, Object>> keyList =
                    new ArrayList<Map<String, Object>>(Arrays.asList(jwk));
            KeyBundle kb = new KeyBundle(keyList);
            addKeyBundle(owner, kb);
        } else {
            ArrayList<Map<String, Object>> keyList =
                    new ArrayList<Map<String, Object>>();

            for(String use : usage) {
                HashMap<String, Object> jwk = new HashMap<String, Object>();
                jwk.put("kty", "oct");
                jwk.put("k", b64Key);
                jwk.put("use", use);
                keyList.add(jwk);
            }
            KeyBundle kb = new KeyBundle(keyList);
            addKeyBundle(owner, kb);
        }
    }

    /**
     * Add a key bundle and bind it to an identifier
     * @param owner Owner of the keys in the keybundle
     * @param keyBundle the KeyBundle instance to add
     */
    public void addKeyBundle(String owner, KeyBundle keyBundle) {
        List<KeyBundle> kbList;
        if(issuerKeys.get(owner) == null) {
            kbList = new ArrayList<>(Arrays.asList(keyBundle));
        } else {
            kbList = issuerKeys.get(owner);
            kbList.add(keyBundle);
        }
        issuerKeys.put(owner, kbList);
    }

    /**
     * Get all owner ID's and their key bundles
     * @return Map of owner IDs and their list of KeyBundles
     */
    public Map<String, List<KeyBundle>> getBundles() {
        return issuerKeys;
    }

    /**
     * Bind one or a list of key bundles to a special identifier.
     * Will overwrite whatever was there before !!
     * @param owner the owner of the keys in the keybundle
     * @param kbList list of keybundles to set
     */
    public void setBundle(String owner, List<KeyBundle> kbList) {
        issuerKeys.put(owner, kbList);
    }

    /**
     * Gets the list of KeyBundles for a specific owner
     * @param owner the owner of the keys in the keybundle
     * @return List of KeyBundles
     */
    public List<KeyBundle> getBundle(String owner) {
        return  issuerKeys.get(owner);
    }

    /**
     * Get all keys that matches a set of search criteria
     * @param keyUse  A key useful for this usage (enc, dec, sig, ver)
     * @param keyType type of key (rsa, ec, oct, ..)
     * @param owner Who is the owner of the keys, "" == me
     * @param kid A Key Identifier
     * @param args dictionary of additional key/value pairs
     * @return A possibly empty list of keys
     */
    public List<Key> getKeys(String keyUse, String keyType, String owner, String kid,
                             Map<String,String> args) {
        String use;
        if(keyUse.equals("dec") || keyUse.equals("enc")) {
            use = "enc";
        } else {
            use = "sig";
        }

        List<KeyBundle> keyBundleList = null;
        if(!Utils.isNullOrEmpty(owner)) {
            keyBundleList = this.issuerKeys.get(owner);

            if(keyBundleList == null) {
                if(owner.endsWith("/")) {
                    keyBundleList = this.issuerKeys.get(owner.substring(0, owner.length()-1));
                } else {
                    keyBundleList = this.issuerKeys.get(owner+"/");
                }
            }
        } else {
            keyBundleList = this.issuerKeys.get(owner);
        }

        if(keyBundleList == null) {
            return new ArrayList<>();
        }

        List<Key> keyListToReturn = new ArrayList<>();
        for(KeyBundle keyBundle : keyBundleList) {
            List<Key> tempKeyList1;
            if(!Utils.isNullOrEmpty(keyType)) {
                tempKeyList1 = keyBundle.get(keyType);
            } else {
                tempKeyList1 = keyBundle.getKeys();
            }

            for(Key key : tempKeyList1) {
                if(key.getInactiveSince() != 0 && !"sig".equals(keyUse)) {
                    continue;
                }
                if(Utils.isNullOrEmpty(key.getUse()) || use.equals(key.getUse())) {
                    if(!Utils.isNullOrEmpty(kid))  {
                        if(kid.equals(key.getKid())) {
                            keyListToReturn.add(key);
                            break;
                        } else
                            continue;
                    } else {
                        keyListToReturn.add(key);
                    }
                }
            }
        }

        // if elliptic curve have to check I have a key of the right curve
        if("EC".equals(keyType) && args.containsKey("alg")) {
            String name = "P-" + args.get("alg").substring(2);
            List<Key> tempKeyList2 = new ArrayList<>();
            List<Key> keyList = new ArrayList<>();
            for(Key key : keyListToReturn) {
                if(key instanceof ECKey) {
                    ECKey ecKey = (ECKey) key;
                    if (!name.equals(ecKey.getCrv()))
                        continue;
                    else
                        tempKeyList2.add(key);
                }
            }
            keyListToReturn = tempKeyList2;
        }

        if("enc".equals(use) && "oct".equals(keyType) && !Utils.isNullOrEmpty(owner)) {
            for(KeyBundle keyBundle : this.issuerKeys.get("")) {
                for(Key key : keyBundle.get(keyType)) {
                    if(key.getInactiveSince() != 0)
                        continue;
                    if(Utils.isNullOrEmpty(key.getUse())  || use.equals(key.getUse())) {
                        keyListToReturn.add(key);
                    }
                }
            }
        }

        return keyListToReturn;
    }

    /**
     * Gets all signing keys of the specific type for the specific owner
     * @param keyType type of key (rsa, ec, oct, ..)
     * @param owner the owner of the keys
     * @param kid the key OD
     * @param args Map of addtional key/value pairs
     * @return List of possibly empty Keys
     */
    public List<Key> getSigningKey(String keyType, String owner, String kid,
                                   Map<String,String> args) {
        return getKeys("sig", keyType, owner, kid, args);
    }

    /**
     * Gets all verification keys of the specific type for the specific owner
     * @param keyType type of key (rsa, ec, oct, ..)
     * @param owner the owner of the keys
     * @param kid the key OD
     * @param args Map of addtional key/value pairs
     * @return List of possibly empty Keys
     */
    public List<Key> getVerifyKey(String keyType, String owner, String kid,
                                  Map<String,String> args) {
        return getKeys("ver", keyType, owner, kid, args);
    }

    /**
     * Gets all encryption keys of the specific type for the specific owner
     * @param keyType type of key (rsa, ec, oct, ..)
     * @param owner the owner of the keys
     * @param kid the key OD
     * @param args Map of addtional key/value pairs
     * @return List of possibly empty Keys
     */
    public List<Key> getEncryptKey(String keyType, String owner, String kid,
                                   Map<String,String> args) {
        return getKeys("enc", keyType, owner, kid, args);
    }

    /**
     * Gets all decryption keys of the specific type for the specific owner
     * @param keyType type of key (rsa, ec, oct, ..)
     * @param owner the owner of the keys
     * @param kid the key OD
     * @param args Map of addtional key/value pairs
     * @return List of possibly empty Keys
     */
    public List<Key> getDecryptKey(String keyType, String owner, String kid,
                                   Map<String,String> args) {
        return getKeys("dec", keyType, owner, kid, args);
    }

    /**
     * Gets Keys for the specific owner, algorithm and usage
     * @param issuer the owner of the keys
     * @param algorithm the algorithm to be used with the key
     * @param usage  A key useful for this usage (enc, dec, sig, ver)
     * @return List of possibly empty keys that match the criteria
     */
    public List<Key> keysByAlgAndUsage(String issuer, String algorithm, String usage) {
        String keyType;
        if(usage.equals("sig") || usage.equals("ver")) {
            keyType = algorithmToKeytypeForJWS(algorithm);
        } else {
            keyType = algorithmToKeytypeForJWE(algorithm);
        }

        return getKeys(usage, keyType, issuer, null, null);
    }

    /**
     * Gets all keys belonging to the specified owner
     * @param issuer the owner of the keys to retrieve
     * @return list of possibly empty keys
     */
    public List<Key> getIssuerKeys(String issuer) {
        List<Key> keyList = new ArrayList<>();
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            keyList.addAll(keyBundle.getKeys());
        }
        return keyList;
    }


    private String algorithmToKeytypeForJWS(String algorithm) {
        if(algorithm == null || algorithm.toLowerCase().equals("none")) {
            return "none";
        } else if(algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
            return "RSA";
        } else if(algorithm.startsWith("HS") || algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ES") || algorithm.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return null;
        }
    }

    private String algorithmToKeytypeForJWE(String algorithm) {
        if(algorithm.startsWith("RSA")) {
            return "RSA";
        } else if(algorithm.startsWith("A")) {
            return "oct";
        } else if(algorithm.startsWith("ECDH")) {
            return "EC";
        } else {
            return null;
        }
    }

    /**
     * Getsa list of owner IDs
     * @return List of owner ID strings
     */
    public List<String> getOwners() {
       return Arrays.asList(issuerKeys.keySet().toArray(new String[0]));
    }

    /**
     * Gets the owner ID that matches the URL
     * @param url URL to match
     * @return owner ID that matches url
     * @throws KeyException
     */
    public String matchOwner(String url) throws KeyException {
        for(String key : this.issuerKeys.keySet()) {
            if(url.startsWith(key)) {
                return key;
            }
        }

        throw new KeyException(String.format("No keys for %s", url));
    }

    /**
     * Fetch keys from another server for the specified owner
     * @param pcr The provider information from OpenID discovery
     * @param issuer The provider URL
     * @param shouldReplace If all previously gathered keys from this provider should be replace
     * @throws ImportException
     * @throws KeyException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public void loadKeys(Map<String,Object> pcr, String issuer, boolean shouldReplace) throws ImportException, KeyException, IOException, JWKException, ValueError {
        logger.debug("loading keys for issuer: " + issuer);

        if(shouldReplace || !this.issuerKeys.keySet().contains(issuer)) {
            this.issuerKeys.put(issuer, new ArrayList<KeyBundle>());
        }
        String jwksUri = (String) pcr.get("jwks_uri");
        if(!Utils.isNullOrEmpty(jwksUri)) {
            addUrl(issuer, jwksUri, null);

        } else {
            Object jwks = pcr.get("jwks");
            if(jwks != null) {
                if(jwks instanceof Map) {
                    List<Map<String, Object>> keys = (List<Map<String, Object>>) ((Map)jwks).get("keys");
                    if(keys != null) {
                        try {
                            addKeyBundle(issuer, new KeyBundle(keys));
                        }
                        catch(ImportException e) {
                        }
                    }
                }
            }
        }
    }

    /**
     * Find a key bundle based on the source of the keys
     * @param source A source url
     * @param issuer The issuer of keys
     * @return KeyBundle matching source and issuer
     */
    public KeyBundle find(String source, String issuer) {
        for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
            if(keyBundle.getSource().equals(source)) {
                return keyBundle;
            }
        }

        return null;
    }

    /**
     * Produces a dictionary that later can be easily mapped into a JSON string representing a JWKS.
     * @param isPrivate whether to include private key information
     * @param issuer the owner of the keys
     * @return A JWKS object that represents the keyjar
     */
    public Map<String,Object> exportJwks(boolean isPrivate, String issuer) {
        List<Map<String, Object>> keys = new ArrayList<>();
        if(issuerKeys.get(issuer) != null) {
            for(KeyBundle keyBundle : this.issuerKeys.get(issuer)) {
                if(keyBundle.getKeys() != null) {
                    for(Key key : keyBundle.getKeys()) {
                        if(key.getInactiveSince() == 0) {
                            try {
                                keys.add(key.serialize(isPrivate));
                            }
                            catch (SerializationNotPossible e) {
                            }
                        }
                    }
                }
            }
        }

        Map<String,Object> keysMap = new HashMap<>();
        keysMap.put("keys", keys);
        return keysMap;
    }

    /**
     * Produces a JSON string representing the JWKS for the specific owner's KeyBundles
     * @param isPrivate whether to include private key information
     * @param issuer the owner of the keys
     * @return JSON string of the JWKS
     */
    public String exportJwksAsJson(boolean isPrivate, String issuer) {
        JSONObject json = new JSONObject(exportJwks(isPrivate, issuer));
        return json.toJSONString();
    }

    /**
     * Import the JWKS object for the specified owner
     * @param jwks Dictionary representation of a JWKS
     * @param issuer Who 'owns' the JWKS
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public void importJwks(Map<String,Object> jwks, String issuer) throws ImportException, IOException, JWKException, ValueError {
        Object keysObj = jwks.get("keys");
        if(keysObj instanceof List) {
            List<Object> keysList = (List<Object>) jwks.get("keys");
            if(!keysList.isEmpty()) {
                if(keysList.get(0) instanceof Map) {
                    List<Map<String, Object>> k2 = (List<Map<String, Object>>)jwks.get("keys");
                    addKeyBundle(issuer, new KeyBundle(k2, "", "jwk", "", null));
                }
            }
        }
    }

    /**
     * Import the JWKS JSON string for the specified owner
     * @param js JSON string representing the JWKS
     * @param issuer Who 'owns' the JWKS
     * @throws ParseException
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public void importJwksAsJson(String js, String issuer) throws ParseException, ImportException, IOException, JWKException, ValueError{
        JSONParser parser = new JSONParser();
        JSONObject json = (JSONObject) parser.parse(js);
        importJwks(json, issuer);
    }

    /**
     * Goes through the complete list of issuers and for each of them removes outdated keys.
     * Outdated keys are keys that has been marked as inactive at a time that is longer ago
     * then some set number of milliseconds. The number of milliseconds a carried in the removeAfter
     * parameter of the constructor
     * @param when milliseconds of when the starting time is. For facilitating testing.
     */
    public void removeOutdated(long when)  {
        List<KeyBundle> keyBundleList;
        for(String owner : this.issuerKeys.keySet()) {
            keyBundleList = new ArrayList<>();
            for(KeyBundle keyBundle : this.issuerKeys.get(owner)) {
                keyBundle.removeOutdated(this.removeAfter, when);
                if(keyBundle.getLength() > 0) {
                    keyBundleList.add(keyBundle);
                }
            }

            if(keyBundleList.size() > 0) {
                this.issuerKeys.put(owner, keyBundleList);
            } else {
                this.issuerKeys.remove(owner);
            }
        }
    }

    /**
     * Adds keys for the specified owner, use, keytype, kid
     * @param keys list of keys to add
     * @param owner the owner of the keys
     * @param use uses for the keys
     * @param keyType key type for the keys
     * @param kid kid of the keys
     * @param noKidIssuer
     * @param allowMissingKid
     * @return list of added keys
     */
    private List<Key> addKey(List<Key> keys, String owner, String use, String keyType, String kid,
                            Map<String,List<String>> noKidIssuer, boolean allowMissingKid) {
        if(!this.issuerKeys.keySet().contains(owner)) {
            logger.error("Issuer " + owner + " not in keyjar");
            return keys;
        }

        if(!Utils.isNullOrEmpty(kid)) {
            for(Key key : this.getKeys(use, keyType, owner, kid, null)) {
                if(key != null && !keys.contains(key)) {
                    keys.add(key);
                }
            }
            return keys;
        } else {
            List<Key> keyList = this.getKeys(use, keyType, owner, "", null);
            if(keyList.size() == 0) {
                return keys;
            } else if(keyList.size() == 1) {
                if(!keys.contains(keyList.get(0))) {
                    keys.add(keyList.get(0));
                }
            } else if(allowMissingKid) {
                keys.addAll(keyList);
            } else if(noKidIssuer != null) {
                List<String> allowedKids = noKidIssuer.get(owner);
                if(allowedKids != null) {
                    for(Key key : keyList) {
                        if(allowedKids.contains(key.getKid())) {
                            keys.add(key);
                        }
                    }
                }
            }
        }
        return keys;
    }

    /**
     * Gets all key for verifying a signed JWT
     * @param jwtString JWT string
     * @param issuer owner or issuer of the JWT
     * @param noKidIssuers list of issuers that do not require kids
     * @param allowMissingKid whether to allow missing kids
     * @param trustJKU whether to trust the JWT's jku header for fetching addtional keys (risky)
     * @return List of usable Keys
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public List<Key> getJWTVerifyKeys(
        String jwtString, String issuer, Map<String, List<String>> noKidIssuers,
        boolean allowMissingKid, boolean trustJKU) throws IOException, JWKException, ValueError
    {
        DecodedJWT jwt = JWT.decode(jwtString);
        String alg = jwt.getAlgorithm();
        String keyType = alg2KeyType(alg);
        String kid = Utils.isNullOrEmpty(jwt.getKeyId()) ? "" : jwt.getKeyId();
        Map<String, List<String>> nki = null;
        if(noKidIssuers == null)
            nki = new HashMap<>();
        else
            nki = noKidIssuers;
        List<Key> keys = getKeys("sig", keyType, "", "", null);
        String iss = Utils.isNullOrEmpty(jwt.getIssuer()) ? issuer : jwt.getIssuer();
        if(!Utils.isNullOrEmpty(iss)) {
            addKey(keys, iss, "sig", keyType, kid, nki, allowMissingKid);
        }
        // First extend the keyjar if allowed
        String jku = jwt.getHeaderClaim("jku").asString();
        if(!Utils.isNullOrEmpty(jku) && !Utils.isNullOrEmpty(iss)) {
            if(find(jku, iss) == null) {
                if(trustJKU) {
                    try {
                        addUrl(iss, jku, null);
                    } catch(ImportException | KeyException e) {

                    }
                }
            }
        }

        String[] claimsList = new String[] {"aud", "client_id"};
        for(String claim : claimsList) {
            Claim payloadClaim = jwt.getClaim(claim);
            if(payloadClaim == null || payloadClaim instanceof NullClaim)
                continue;
            if(claim.equals("aud")) {
                List<String> audList = null;
                if(payloadClaim.asString() != null) {
                    audList = new ArrayList<>();
                    audList.add(payloadClaim.asString());
                } else if(payloadClaim.asList(String.class) != null) {
                    audList = payloadClaim.asList(String.class);
                }
                if(audList != null) {
                    for(String aud: audList) {
                        addKey(keys, aud, "sig", keyType, kid, nki, allowMissingKid);
                    }
               }
            } else {
                keys = addKey(keys, payloadClaim.asString(), "sig", keyType, kid, nki, allowMissingKid);
            }
        }

        // Only want the public keys. Symmetric keys are also OK.
        List<Key> returnKeys = new ArrayList<>();
        for(Key key : keys) {
            if(key.isPublicKey()) {
                returnKeys.add(key);
            }
        }
        return returnKeys;
    }


    /**
     * Copies this KeyJar instance
     * @return new KeyJar copy
     */
    public KeyJar copy() {
        KeyJar keyJar = new KeyJar();
        for(String owner : this.issuerKeys.keySet()) {
            for(KeyBundle kb : issuerKeys.get(owner)) {
                keyJar.addKeyBundle(owner, kb.copy());
            }
         }
        return keyJar;
    }

    /**
     * Build a keyjar given a configuration template of the type
     * Configuration of the type :
     *   keys = [
     *    {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
     *    {"type": "EC", "crv": "P-256", "use": ["sig"]},
     *    {"type": "EC", "crv": "P-256", "use": ["enc"]}
     *    ]
     * @param keyConf A list of configuration objects
     * @param kidTemplate string template for KIDs
     * @param keyJar an existing keyjar if any
     * @param kidd
     * @return a new keyjar with keys generated according to the configuration
     */
    public static KeyJar buildKeyJar(List<Object> keyConf, String kidTemplate, KeyJar keyJar, Map<String, Object> kidd) {
        if(keyJar == null )
            keyJar = new KeyJar();

        if(kidd == null) {
            kidd = new HashMap<>();
            kidd.put("sig", new HashMap<>());
            kidd.put("enc", new HashMap<>());
        }

        int kid = 0;
        Map<String, Object> jwks = new HashMap<>();
        List<Object> keysList = new ArrayList<>();
        jwks.put("keys", new ArrayList());

        for(Object specConf : keyConf) {
            Map<String, Object>  spec = (Map<String,Object>) specConf;
            String type = spec.get("type") != null ? ((String)spec.get("type")).toUpperCase() : "";
            KeyBundle kb = null;
            if("RSA".equals(type)) {
                if(spec.get("key") != null) {
                    try {
                        kb = new KeyBundle(null, "file://" + (String) spec.get("key"), "der", type, (List<String>) spec.get("use"));
                    } catch(Exception e) {
                        kb = newRSAKey(spec);
                    }
                } else {
                    kb = KeyBundle.rsaInit(spec);
                }
            } else if(type.equals("EC")) {
                kb = KeyBundle.ecInit(spec);
            }
            if(kb != null) {
                for(Key key : kb.getKeys()) {
                    if(!Utils.isNullOrEmpty(kidTemplate)) {
                        key.setKid(String.format(kidTemplate, kid++));
                    } else {
                        key.addKid();
                    }
                    Map<String, Object> usage = (Map<String, Object> )kidd.get(key.getUse());
                    if(usage == null) {
                        usage = new HashMap<>();
                    }
                    usage.put(key.getKty(), key.getKid());
                    kidd.put(key.getUse(), usage);
                }

                for(Key k : kb.getKeys()) {
                    if(!k.getKty().equals("oct")) {
                        try {
                            keysList.add(k.serialize());
                        }catch(SerializationNotPossible e) {

                        }
                    }
                }
                jwks.put("keys", keysList);
                keyJar.addKeyBundle("", kb);
            }
        }
        // Python returns jwks, keyjar, kidd
        return keyJar;
    }

   private String alg2KeyType(String alg) {
        if(Utils.isNullOrEmpty(alg) || alg.toLowerCase().equals("none")) {
            return "none";
        } else if(alg.startsWith("RS") || alg.startsWith("PS")) {
            return "RSA";
        } else if(alg.startsWith("HS") || alg.startsWith("A")) {
            return "oct";
        } else if(alg.startsWith("ES") || alg.startsWith("ECDH-ES")) {
            return "EC";
        } else {
            return "";
        }
    }

    private static KeyBundle newRSAKey(Map<String, Object> spec) {
        if(spec.get("name") == null) {
            if(spec.get("key") != null) {
                String key = (String)spec.get("key");
                int index = key.indexOf('/');
                if(index != -1) {
                    spec.put("path", key.substring(0, index -1));
                    spec.put("name", key.substring(index + 1));
                } else {
                    spec.put("name", key);
                }
            }
        }
        return KeyBundle.rsaInit(spec);
    }

    /**
     * Gets the time in milliseconds that keys will be removed
     * @return number of milliseconds that  will be removed
     */
    public long getRemoveAfter() {
        return removeAfter;
    }

    /**
     * Sets the time in milliseconds that keys will be removed
     * @param removeAfter number of milliseconds after which keys will be removed
     */
    public void setRemoveAfter(long removeAfter) {
        this.removeAfter = removeAfter;
    }

}

