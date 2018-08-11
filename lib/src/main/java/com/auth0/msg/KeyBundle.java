
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UpdateFailed;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.fasterxml.jackson.core.JsonParser;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class KeyBundle {

    final private static Logger logger = LoggerFactory.getLogger(KeyBundle.class);
    private static final Map<String, String> map =
            ImmutableMap.of("dec", "enc",
                    "enc", "enc",
                    "ver", "sig",
                    "sig", "sig"
            );
    private List<Key> keys;
    private JSONObject impJwks;
    private String source;
    private long cacheTime;
    private boolean verifySSL;
    private String fileFormat;
    private String keyType;
    private List<String> keyUsage;
    private boolean remote;
    private long timeOut;
    private String eTag;
    private long lastUpdated;

    /**
     * Contains a set of keys that have a common origin.
     The sources can be serveral:
     - A dictionary provided at the initialization, see keys below.
     - A list of dictionaries provided at initialization
     - A file containing one of: JWKS, DER encoded key
     - A URL pointing to a webpages from which an JWKS can be downloaded

     :param keys: A dictionary or a list of dictionaries
     with the keys ["kty", "key", "alg", "use", "kid"]
     :param source: Where the key set can be fetch from
     :param verify_ssl: Verify the SSL cert used by the server
     :param fileformat: For a local file either "jwk" or "der"
     :param keytype: Iff local file and 'der' format what kind of key it is.
     presently only 'rsa' is supported.
     :param keyusage: What the key loaded from file should be used for.
     Only applicable for DER files
     * @param keys
     * @param source
     * @param cacheTime
     * @param verifySSL
     * @param fileFormat
     * @param keyType
     * @param keyUsage
     * @throws ImportException
     */
    public KeyBundle(List<Map<String, Object>> keys, String source, long cacheTime,
                     boolean verifySSL,String fileFormat, String keyType, List<String> keyUsage)
        throws ImportException, IOException, JWKException, ValueError {
        this.keys = new ArrayList<Key>();
        this.cacheTime = cacheTime == 0 ? 300000 : cacheTime;
        this.verifySSL = verifySSL;
        this.fileFormat = Utils.isNullOrEmpty(fileFormat) ? "" : fileFormat.toLowerCase();
        this.keyType = keyType;
        this.keyUsage = keyUsage;
        this.remote = false;
        this.timeOut = 0;
        this.impJwks = new JSONObject();
        this.lastUpdated = 0;
        this.eTag = "";

        if (keys != null) {
            this.source = null;
            doKeys(keys);
        } else if(!Utils.isNullOrEmpty(source)){
            if (source.startsWith("file://")) {
                this.source = source.substring(7);
            } else if (source.startsWith("http://") || source.startsWith("https://")) {
                this.source = source;
                this.remote = true;
            } else {
                if (new HashSet<String>(Arrays.asList("rsa", "der", "jwks")).contains(
                    fileFormat.toLowerCase())) {
                    File file = new File(source);
                    if (file.exists() && file.isFile()) {
                        this.source = source;
                    } else {
                        throw new ImportException("No such file exists");
                    }
                } else {
                    throw new ImportException("Unknown source");
                }
            }

            if (!this.remote ) {
                if (this.fileFormat.equals("jwks") || this.fileFormat.equals("jwk")) {
                    try {
                        this.doLocalJwk(this.source);
                    } catch (UpdateFailed updateFailed) {
                        logger.error("Local key updated from " + this.source + " failed.");
                    }
                } else if (this.fileFormat.equals("der")) {
                    doLocalDer(this.source, this.keyType, this.keyUsage);
                }
            }
        }
    }


    public KeyBundle() throws ImportException, IOException, JWKException, ValueError {
        this(null, "", 0, true, "jwk", "RSA", null);
    }

    public KeyBundle(List<Map<String, Object>> keyList, String keyType) throws ImportException, IOException, JWKException, ValueError {
        this(keyList, "", 0, true, "jwk", keyType, null);
    }

    public KeyBundle(List<Map<String, Object>> keyList) throws ImportException, IOException, JWKException, ValueError {
        this(keyList, "", 0, true, "jwk", "", null);
    }

    public KeyBundle(List<Map<String, Object>> keyList, String keyType, List<String> usage)
        throws ImportException, IOException, JWKException, ValueError {
        this(keyList, "", 0, true, "jwk", keyType, usage);
    }

    public KeyBundle(String source, boolean verifySSL) throws ImportException, IOException, JWKException, ValueError {
        this(null, source, 0, verifySSL, "jwk", "RSA", null);
    }

    public KeyBundle(String source, String fileFormat, List<String> usage) throws ImportException, IOException, JWKException, ValueError {
        this(null, source, 0, true, fileFormat, "RSA", usage);
    }

    public KeyBundle(String keyType) throws ImportException, IOException, JWKException, ValueError {
        this(null, "", 0, true, "", keyType, null);
    }

    public KeyBundle(String keyType, List<String> usage) throws ImportException, IOException, JWKException, ValueError {
        this(null, "", 0, true, "", keyType, usage);
    }

    public String getSource() {
        return source;
    }

    /**
     * Go from JWK description to binary keys
     * @param keys List of JWKs
     */
    public void doKeys(List<Map<String, Object>> keys) {
        for(Map<String, Object> key :keys) {
            String keyType = (String) key.get("kty");
            String keyUse = (String) key.get("use");

            List<String> usage;
            if(!Utils.isNullOrEmpty(keyUse))
                usage = harmonizeUsage(Arrays.asList(keyUse));
            else
                usage = Arrays.asList("sig", "enc");
            key.remove("use");
            for(String use : usage) {
                Key keyInstance = null;
                try {
                    String alg = (String) key.get("alg");
                    String kid = (String) key.get("kid");
                    String[] x5c = new String[0];
                    if(key.get("x5c") != null)
                        x5c = ((List<String>)key.get("x5c")).toArray(new String[0]);
                    String x5t= (String) key.get("x5t");
                    String x5u = (String) key.get("x5u");

                    if("RSA".equals(keyType)) {
                        String n = (String) key.get("n");
                        String e = (String) key.get("e");
                        String d = (String) key.get("d");
                        String p = (String) key.get("p");
                        String q = (String) key.get("q");
                        String dp = (String) key.get("dp");
                        String dq = (String) key.get("dq");
                        String qi = (String) key.get("qi");
                        String oth = (String) key.get("oth");

                        keyInstance = new RSAKey(alg, use, kid, x5c,x5t, x5u, null,
                            n, e, d, p, q, dp, dq, qi, oth, null);
                    } else if("EC".equals(keyType)) {
                        String x = (String) key.get("x");
                        String y = (String) key.get("y");
                        String d = (String) key.get("d");
                        String curve = (String) key.get("crv");
                        keyInstance = new ECKey(alg, use, kid, null, curve, x, y, d, null);
                    } else if("oct".equals(keyType)) {
                        String k = (String) key.get("k");
                        keyInstance = new SYMKey(alg, use, kid, null, x5c, x5t, x5u, k, null);
                    } else
                        continue;
                    this.keys.add(keyInstance);
                }
                catch(Exception | SerializationNotPossible e) {
                    System.out.println(e.toString());
                }
            }
        }
    }

    private static List<String> harmonizeUsage(List<String> uses) {
        Set<String> keys = map.keySet();
        Set<String> usagesSet = new HashSet<>();
        for (String use : uses) {
            if (keys.contains(use)) {
                usagesSet.add(map.get(use));
            }
        }
        return new ArrayList<>(usagesSet);
    }

    public void doLocalJwk(String fileName) throws UpdateFailed {
        JSONParser parser = new JSONParser();
        try {
            Object obj = parser.parse(new FileReader(
                    fileName));
            JSONObject jsonObject = (JSONObject) obj;
            JSONArray keys = (JSONArray) jsonObject.get("keys");
            if(keys != null)
                doKeys(keys);
        } catch (Exception e) {
            logger.error("Now 'keys' keyword in JWKS");
            throw new UpdateFailed("Local key updated from " + fileName + " failed.");
        } finally {
            this.lastUpdated = System.currentTimeMillis();
        }
    }

    public void doLocalDer(String fileName, String keyType, List<String> keyUsage) throws ValueError, JWKException, IOException {
        if(!keyType.toLowerCase().equals("rsa")) {
            throw new ValueError("Invalid key type");
        }
        if(keyUsage == null || keyUsage.size() == 0) {
            keyUsage = new ArrayList<String>();
            keyUsage.add("enc");
            keyUsage.add("sig");

        } else {
            keyUsage = harmonizeUsage(keyUsage);

        }
        for(String use : keyUsage) {
            java.security.Key key = RSAKey.getPemRSAKey(fileName);
            RSAKey rsaKey = RSAKey.loadKey(key);
            rsaKey.setUse(use);
            keys.add(rsaKey);
        }
        lastUpdated = System.currentTimeMillis();
    }

    public boolean doRemote() throws UpdateFailed, KeyException {
        // TODO Implement caching
        // TODO allowing unverified SSL connections (e.g. no trusts)
//        Map<String, Object> args = new HashMap<>();
//        args.put("verify", this.verifySSL);
//        if (!this.eTag.isEmpty()) {
//            JSONObject jsonObject = new JSONObject();
//            jsonObject.put("If-None-Match", this.eTag);
//            args.put("headers", jsonObject);
//        }


        int statusCode;
        HttpResponse response;
        try {
            logger.debug("KeyBundle fetch keys from: " + this.source);
            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpClient httpclient = new DefaultHttpClient();
            HttpGet httpget = new HttpGet(this.source);
            response = httpclient.execute(httpget);
            statusCode = response.getStatusLine().getStatusCode();
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new UpdateFailed("Couldn't make GET request to url: " + this.source);
        }

        if (statusCode == 304) {
            this.timeOut = System.currentTimeMillis() + this.cacheTime;
            this.lastUpdated = System.currentTimeMillis();

            JSONArray keys = (JSONArray) this.impJwks.get("keys");
            if (keys != null) {
                doKeys(keys);
            } else {
                logger.error("No 'keys' keyword in JWKS");
                throw new UpdateFailed("No 'keys' keyword in JWKS");
            }
        } else if (statusCode == 200) {
            this.timeOut = System.currentTimeMillis() + this.cacheTime;
            try {
                this.impJwks = parseRemoteResponse(response);
            } catch (Exception exception) {
                exception.printStackTrace();
            }

            if (!this.impJwks.keySet().contains("keys")) {
                throw new UpdateFailed(this.source);
            }

            logger.debug("Loaded JWKS: " + response.toString() + " from " + this.source);
            JSONArray keys = (JSONArray) this.impJwks.get("keys");
            if (keys != null) {
                doKeys(keys);
            } else {
                logger.error("No 'keys' keyword in JWKS");
                throw new UpdateFailed("No 'keys' keyword in JWKS");
            }

            Header etagHeader = response.getFirstHeader("Etag");
            if (etagHeader != null) {
                this.eTag = etagHeader.getValue();
            }
        } else {
            throw new UpdateFailed("Source: " + this.source + " status code: " + statusCode);
        }

        this.lastUpdated = System.currentTimeMillis();
        return true;
    }

    private JSONObject parseRemoteResponse(HttpResponse response)
        throws IOException, ParseException {
        Header header = response.getFirstHeader("Content-Type");
        if(header == null || !header.getValue().contains("application/json"))
            logger.warn("Wrong content-type");
        logger.debug(String.format("Loaded JWKS: %s from %s", response.toString(), this.source));
        return (JSONObject) new JSONParser().parse(EntityUtils.toString(response.getEntity()));
    }

    private boolean upToDate() {

        boolean result = false;
        if (!this.keys.isEmpty()) {
            if (this.remote) {
                if (System.currentTimeMillis() > this.timeOut) {
                    if (update()) {
                        result = true;
                    }
                }
            }
        } else if (this.remote) {
            if (update()) {
                result = true;
            }
        }
        return result;
    }

    public boolean update() {
        boolean result = true;
        if (!Utils.isNullOrEmpty(this.source)) {
            List<Key> keys = this.keys;
            this.keys = new ArrayList<Key>();
            try {
                if (!this.remote) {
                    if (this.fileFormat.equals("jwks")) {
                        this.doLocalJwk(this.source);
                    } else if (this.fileFormat.equals("der")) {
                        doLocalDer(source, keyType, keyUsage);
                    }
                } else {
                    result = doRemote();
                }
            } catch (Exception exception) {
                logger.error("Key bundle updated failed: " + exception.toString());
                this.keys = keys;
                return false;
            }

            long now = System.currentTimeMillis();
            for (Key key : keys) {
                if (!this.keys.contains(key)) {
                    if(key.getInactiveSince() == 0)
                        key.setInactiveSince(now);
                    this.keys.add(key);
                }
            }
        }
        return result;
    }


    /**
     *        """
     Return a list of keys. Either all keys or only keys of a specific type

     :param typ: Type of key (rsa, ec, oct, ..)
     :return: If typ is undefined all the keys as a dictionary
     otherwise the appropriate keys in a list
     """

     * @param keyType
     * @return
     */
    public List<Key> get(String keyType) {

        this.upToDate();
        if (!Utils.isNullOrEmpty(keyType)) {
            List<String> types = Arrays.asList(keyType.toLowerCase(), keyType.toUpperCase());
            List<Key> keys = new ArrayList<Key>();
            for (Key key : this.keys) {
                if (types.contains(key.getKty())) {
                    keys.add(key);
                }
            }
            return keys;
        } else {
            return this.keys;
        }
    }

    public List<Key> getKeys() {
        this.upToDate();
        return this.keys;
    }

    public List<Key> getActiveKeys() {
        List<Key> activeKeys = new ArrayList<>();
        for (Key key : this.keys) {
            if (key.getInactiveSince() == 0) {
                activeKeys.add(key);
            }
        }

        return activeKeys;
    }

    public void removeKeysByType(String keyType) {
        List<String> types = Arrays.asList(keyType.toLowerCase(), keyType.toUpperCase());

        Iterator<Key> it = keys.iterator();
        while(it.hasNext()) {
            Key key = it.next();
            if(types.contains(key.getKty())) {
                keys.remove(key);
            }
        }
    }

    public String toString() {
        try {
            return this.jwks();
        }
        catch(SerializationNotPossible e) {
            return e.toString();
        }
    }

    public String jwks() throws SerializationNotPossible {
        return jwks(false);
    }

    public String jwks(boolean isPrivate) throws SerializationNotPossible{
        this.upToDate();
        JSONObject jwkObject = new JSONObject();
        JSONArray keys = new JSONArray();
        for (Key keyIndex : this.keys) {
            Map<String, Object> key;
            if (isPrivate) {
                key = keyIndex.serialize(true);
            } else {
                key = keyIndex.toDict();
            }
            keys.add(key);
        }
        jwkObject.put("keys", keys);
        return  jwkObject.toJSONString();
    }

    public void append(Key key) {
        this.keys.add(key);
    }

    public void remove(Key key) {
        this.keys.remove(key);
    }

    public int getLength() {
        return this.keys.size();
    }

    public Key getKeyWithKid(String kid) {
        for (Key key : this.keys) {
            if (key.getKid().equals(kid)) {
                return key;
            }
        }
        update();
        for (Key key : this.keys) {
            if (key.getKid().equals(kid)) {
                return key;
            }
        }
        return null;
    }

    public List<String> getKids() {
        this.upToDate();
        List<String> kids = new ArrayList<>();
        for (Key key : this.keys) {
            if (!Utils.isNullOrEmpty(key.getKid())) {
                kids.add(key.getKid());
            }
        }

        return kids;
    }

    public void markAsInactive(String kid) {
        Key key = getKeyWithKid(kid);
        key.setInactiveSince(System.currentTimeMillis());
    }

    public void removeOutdated(long after, long when){
        long now;
        if (when != 0) {
            now = when;
        } else {
            now = System.currentTimeMillis();
        }

        List<Key> keys = new ArrayList<>();
        for (Key key : this.keys) {
            if (!(key.getInactiveSince() > 0 && (key.getInactiveSince() + after < now))) {
                keys.add(key);
            }
        }
        this.keys = keys;
    }

    public KeyBundle copy() {
        try {
            KeyBundle keyBundle = new KeyBundle();
            keyBundle.keys.addAll(this.keys);
            keyBundle.cacheTime = cacheTime;
            keyBundle.verifySSL = verifySSL;
            if (!Utils.isNullOrEmpty(source)) {
                keyBundle.source = source;
                keyBundle.fileFormat = fileFormat;
                keyBundle.keyType = keyType;
                keyBundle.keyUsage = keyUsage;
                keyBundle.remote = remote;
            }
            return keyBundle;
        }
        catch (ImportException | IOException | JWKException | ValueError e) {

        }
        return null;
    }


    public static KeyBundle keyBundleFromLocalFile(String filename, String type, List<String> usage)
        throws ImportException, UnknownKeyType, IOException, JWKException, ValueError {
        usage = harmonizeUsage(usage);
        KeyBundle keyBundle;
        type = type.toLowerCase();
        if (type.equals("jwks")) {
            keyBundle = new KeyBundle(filename, "jwks", usage);
        } else if (type.equals("der")) {
            keyBundle = new KeyBundle(filename, "der", usage);
        } else {
            throw new UnknownKeyType("Unsupported key type");
        }
        return keyBundle;
    }

    public void dumpJwks(List<KeyBundle> keyBundleList, String filename, boolean isPrivate) {
        List<Map<String, Object>> keys = new ArrayList<>();
        for(KeyBundle keyBundle : keyBundleList) {
            for(Key key : keyBundle.getKeys()) {
                if(!"oct".equals(key.getKty()) && key.inactiveSince == 0) {
                    try {
                        keys.add(key.serialize(isPrivate));
                    } catch(SerializationNotPossible e) {
                    }
                }
            }
        }
        Map<String, Object> jsonKeys = new HashMap<>();
        jsonKeys.put("keys", keys);

        JSONObject jsonObject = new JSONObject(jsonKeys);
        System.out.println(jsonObject.toJSONString());
    }


    /**
     * Mints a new RSA key pair and stores it in a file.
     * :param name: Name of the key file. 2 files will be created one with
     * the private key the name without extension and the other containing
     * the public key with '.pub' as extension.
     * :param path: Path to where the key files are stored
     * :param size: RSA key size
     * :return: RSA key
     * @param name
     * @param path
     * @param size
     * @param use
     */
    public static java.security.PrivateKey createStoreRSAKeyPair(String name, String path, int size, String use) {
        // TODO

        if(Utils.isNullOrEmpty(name)) {
            name = "oidcmsg";
        }
        if(Utils.isNullOrEmpty(path)) {
            path = ".";
        }
        if(!path.endsWith(File.separator)) {
            path += File.separator;
        }
        File directory = new File(path);
        if (! directory.exists()){
            directory.mkdirs();
        }
        if(!Utils.isNullOrEmpty(use)) {
            name += "_" + use;
        }
        KeyPair keyPair =  RSAKey.generateRSAKeyPair(size);
        if(keyPair != null) {
            try {
                KeyUtils.writeRSAPemFile(path + name, keyPair.getPrivate());
                KeyUtils.writeRSAPemFile(path + name + ".pub", keyPair.getPublic());
            } catch(IOException e) {

            }
            return keyPair.getPrivate();
        } else {
            return null;
        }
    }

    /**
     *
     * Initiates a KeyBundle instance
     * containing newly minted RSA keys according to a spec.
     * Example of specification::
     * {'name': 'myrsakey', 'path': 'keystore', 'size':2048,
     * 'use': ['enc', 'sig'] }
     * Using the spec above 2 RSA keys would be minted, one for
     * encryption and one for signing.
     *
     * @param spec configuration specification for the keybundle
     * @return new Keybundle containing the new RSAKey
     * @throws ImportException
     * @throws IOException
     */
    public static KeyBundle rsaInit(Map<String, Object> spec) {
        KeyBundle kb = null;
        try {
            String name = (String) spec.get("name");
            String path = (String) spec.get("path");
            long size = spec.get("size") == null ? 2048 : ((Long) spec.get("size")).longValue();

            kb = new KeyBundle("RSA");
            List<String> usage = new ArrayList<>();
            if(spec.get("use") != null) {
                if(spec.get("use") instanceof List) {
                    usage.addAll((List) spec.get("use"));
                } else if(spec.get("use") instanceof String) {
                    usage.add((String)spec.get("use"));
                }
            }
            for(String use : harmonizeUsage(usage)) {
                java.security.Key key = KeyBundle.createStoreRSAKeyPair(name, path, (int)size, use);
                if(key != null) {
                    kb.append(new RSAKey(key, use));
                }
            }
        } catch(ImportException | IOException | JWKException | ValueError e) {

        }
        return kb;
    }


    /**
     * Creates a Keybundle with a newly generated EC key
     * @param spec Key specifics of the form: {"type": "EC", "crv": "P-256", "use": ["sig"]}
     * @return keybundle with the new EC key
     */
    public static KeyBundle ecInit(Map<String, Object> spec) {
        List<String> usage = (List<String>) spec.get("use");
        if(usage == null) {
            usage = new ArrayList<>();
        }
        try {
            KeyBundle kb = new KeyBundle("EC", usage);
            String curve = spec.get("crv") == null ? "P-256" : (String) spec.get("crv");
            KeyPair keyPair = ECKey.generateECKeyPair(curve);
            if(keyPair != null) {
                for(String use : usage) {
                    ECKey ecKey = new ECKey("", use, "", keyPair.getPrivate(), curve, "", "", "", null);
                    kb.append(ecKey);
                }
                return kb;
            }
        } catch(ImportException | HeaderError | ValueError | SerializationNotPossible | JWKException | IOException e) {

        }
        return null;
    }
}

