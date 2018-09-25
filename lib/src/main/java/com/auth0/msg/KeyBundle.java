
package com.auth0.msg;

import com.auth0.jwt.exceptions.oicmsg_exceptions.HeaderError;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.SerializationNotPossible;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UpdateFailed;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
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

/**
 * Contains a set of keys that have a common origin.
 * The sources can be serveral:
 * - A dictionary provided at the initialization, see keys below.
 * - A list of dictionaries provided at initialization
 * - A file containing one of: JWKS, DER encoded key
 * - A URL pointing to a webpages from which an JWKS can be downloaded
 */
public class KeyBundle {

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
     * Constructs a new KeyBundle instance
     *
     * @param keys A list of dictionaries with the keys ["kty", "key", "alg", "use", "kid"]
     * @param source Where the key set can be fetch from (file, http(s))
     * @param cacheTime cache time in milliseconds
     * @param verifySSL whether to verify SSL connection for https sources (unimplemented)
     * @param fileFormat file format of source (jwk, der)
     * @param keyType If local file and 'der' format what kind of key it is.
     *                Presently only 'rsa' is supported.
     * @param keyUsage What the key loaded from file should be used for. Only applicable for
     *                 DER files. (sig, enc)
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
                    }
                } else if (this.fileFormat.equals("der")) {
                    doLocalDer(this.source, this.keyType, this.keyUsage);
                }
            }
        }
    }


    /**
     * Constructs an empty KeyBundle instance
     *
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle() throws ImportException, IOException, JWKException, ValueError {
        this(null, "", 0, true, "jwk", "RSA", null);
    }

    /**
     * Constructs a KeyBundle instance with list of dictionaries with the keys
     * ["kty", "key", "alg", "use", "kid"]
     * @param keyList list of dictionaries with the keys ["kty", "key", "alg", "use", "kid"] and
     *                specific key information
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle(List<Map<String, Object>> keyList) throws ImportException, IOException, JWKException, ValueError {
        this(keyList, "", 0, true, "jwk", "", null);
    }

    /**
     * Constructs a KeyBundle using only a source and whether to verify SSL connections
     * @param source file or URI resource to fetch JWKs
     * @param verifySSL
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle(String source, boolean verifySSL) throws ImportException, IOException, JWKException, ValueError {
        this(null, source, 0, verifySSL, "jwk", "RSA", null);
    }

    /**
     * Constructs a KeyBundle using only a source and usage list
     * @param source file or URI resource to fetch JWKs
     * @param fileFormat file format of source (jwk, der)
     * @param usage What the key loaded from file should be used for. Only applicable for
     *              DER files. (sig, enc)
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle(String source, String fileFormat, List<String> usage) throws ImportException, IOException, JWKException, ValueError {
        this(null, source, 0, true, fileFormat, "RSA", usage);
    }

    /**
     * Constructs an empty KeyBundle for storing keys of specified type
     * @param keyType If local file and 'der' format what kind of key it is.
     *                Presently only 'rsa' is supported.
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle(String keyType) throws ImportException, IOException, JWKException, ValueError {
        this(null, "", 0, true, "", keyType, null);
    }

    /**
     * Construct a KeyBundle of the specified keytype and usage
     * @param keyType If local file and 'der' format what kind of key it is.
     *                Presently only 'rsa' is supported.
     * @param usage What the key loaded from file should be used for. Only applicable for
     *              DER files. (sig, enc)
     * @throws ImportException
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
    public KeyBundle(String keyType, List<String> usage) throws ImportException, IOException, JWKException, ValueError {
        this(null, "", 0, true, "", keyType, usage);
    }

    /**
     * Gets the source of the KeyBundle
     * @return file or URI resource string
     */
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
                        List<Map<String, String>> oth = (List<Map<String, String>>) key.get("oth");

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
                catch(Exception e) {
                }
            }
        }
    }

    /**
     * Creates a set of usages for the specified usages
     * @param uses list of usages (dec, enc, ver, sig)
     * @return
     */
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

    /**
     * Load JWK fro local file and add to internal key list
     * @param fileName path to local JWK file
     * @throws UpdateFailed
     */
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
            throw new UpdateFailed("Local key updated from " + fileName + " failed.");
        } finally {
            this.lastUpdated = System.currentTimeMillis();
        }
    }

    /**
     * Load a DER encoded file and create a key from it and store it
     * @param fileName filename of local DER encode file
     * @param keyType key type. Presetly only 'rsa" is supported
     * @param keyUsage list of usages (enc, sig)
     * @throws ValueError
     * @throws JWKException
     * @throws IOException
     */
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

    /**
     * Load a JWKS from a URI and store the keys
     * @return whether load was successful
     * @throws UpdateFailed
     * @throws KeyException
     */
    public boolean doRemote() throws UpdateFailed, KeyException {
        // TODO Implement caching
        // TODO allowing unverified SSL connections (e.g. no trusts)
        int statusCode;
        HttpResponse response;
        try {
            HttpClient httpClient = HttpClientBuilder.create().build();
            HttpClient httpclient = new DefaultHttpClient();
            HttpGet httpget = new HttpGet(this.source);
            response = httpclient.execute(httpget);
            statusCode = response.getStatusLine().getStatusCode();
        } catch (Exception e) {
            throw new UpdateFailed("Couldn't make GET request to url: " + this.source);
        }

        if (statusCode == 304) {
            this.timeOut = System.currentTimeMillis() + this.cacheTime;
            this.lastUpdated = System.currentTimeMillis();

            JSONArray keys = (JSONArray) this.impJwks.get("keys");
            if (keys != null) {
                doKeys(keys);
            } else {
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

            JSONArray keys = (JSONArray) this.impJwks.get("keys");
            if (keys != null) {
                doKeys(keys);
            } else {
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

    /**
     * Parses the HTTP response
     * @param response The HTTP rEsponse
     * @return a JSON object representing the contents of the source
     * @throws IOException
     * @throws ParseException
     */
    private JSONObject parseRemoteResponse(HttpResponse response)
        throws IOException, ParseException {
        Header header = response.getFirstHeader("Content-Type");
        return (JSONObject) new JSONParser().parse(EntityUtils.toString(response.getEntity()));
    }

    /**
     * Checks to see if keys are up todate
     * @return
     */
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

    /**
     * Reload the keys if necessary. This is a forced update, will happen even if cache time has
     * not elapsed. Replaced keys will be marked as inactive and not removed.
     * @return whether update was successful
     */
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
     *
     * Get a list of keys. Either all keys or only keys of a specific type
     * @param keyType Type of key (rsa, ec, oct, ..)
     * @return if keyType is blank/null all the keys as a dictionary
     *         otherwise the appropriate keys in a list
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

    /**
     * Gets all the Keys in this KeyBundle after updating them
     * @return list of all Keys
     */
    public List<Key> getKeys() {
        this.upToDate();
        return this.keys;
    }

    /**
     * Gets the list of active keys (keys that haven't been marked inactive)
     * @return List of active Keys
     */
    public List<Key> getActiveKeys() {
        List<Key> activeKeys = new ArrayList<>();
        for (Key key : this.keys) {
            if (key.getInactiveSince() == 0) {
                activeKeys.add(key);
            }
        }

        return activeKeys;
    }

    /**
     * Remove keys that are of a specific kind
     * @param keyType type of key (rsa, ec, oct, ...)
     */
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

    /**
     * Gets the JWK representation of this keybundle
     * @return JWK string
     */
    public String toString() {
        try {
            return this.jwks();
        }
        catch(SerializationNotPossible e) {
            return e.toString();
        }
    }

    /**
     * Create a JWKS of the using the public key information in this KeyBundle
     * @return
     * @throws SerializationNotPossible
     */
    public String jwks() throws SerializationNotPossible {
        return jwks(false);
    }

    /**
     * Create a JWKS of the keys in the KeyBundle
     * @param isPrivate whether to include private key information
     * @return  JWKS representation of the keys in this bundle
     * @throws SerializationNotPossible
     */
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

    /**
     * Adds a key to this KeyBundle
     * @param key
     */
    public void append(Key key) {
        this.keys.add(key);
    }

    /**
     * Removes the specified key from this KeyBundle
     * @param key The key that should be removed
     */
    public void remove(Key key) {
        this.keys.remove(key);
    }

    /**
     * Gets the number of keys in this KeyBundle
     * @return number of keys in this KeyBundle
     */
    public int getLength() {
        return this.keys.size();
    }


    /**
     * Return the key that has specific key ID (kid)
     * @param kid The key ID
     * @return The Key or null
     */
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


    /**
     * Return a list of key IDs. Note that list list may be shorter then the list of keys.
     * @return A list of all the key IDs that exists in this bundle
     */
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

    /**
     * Mark a specific key as inactive based on the keys KeyID
     * @param kid The key ID
     */
    public void markAsInactive(String kid) {
        Key key = getKeyWithKid(kid);
        key.setInactiveSince(System.currentTimeMillis());
    }

    /**
     * Remove keys that should not be available any more. Outdated means that the key was marked
     * as inactive at a time that was longer ago then what is given in 'after'.
     * @param after The length of time in milliseconds the key will remain in the KeyBundle before
     *              it should be removed.
     * @param when Time in milliseconds of starting time. To make it easier to test
     */
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

    /**
     * Creates a copy of this KeyBundle
     * @return new KeyBundle copy
     */
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


    /**
     * Create a KeyBundle based on the content in a local file
     * @param filename name of file
     * @param type type of content(der or jwks)
     * @param usage What the keys should be used for (sig, enc)
     * @return The created KeyBundle
     * @throws ImportException
     * @throws UnknownKeyType
     * @throws IOException
     * @throws JWKException
     * @throws ValueError
     */
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

    /**
     * Write a JWK to a file. Will ignore symmetric keys !!
     * @param keyBundleList List of KeyBundles
     * @param filename
     * @param isPrivate
     */
    public static void dumpJwks(List<KeyBundle> keyBundleList, String filename, boolean isPrivate)
    throws  FileNotFoundException
    {
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
        PrintWriter out = null;
        try {
            out = new PrintWriter(filename);
            out.print(jsonObject.toJSONString());
        } finally {
            if(out != null) {
                out.close();
            }
        }
    }


    /**
     * Mints a new RSA key pair and stores it in a file.
     * @param name Name of the key file. 2 files will be created one with
     *             the private key the name without extension and the other containing
     *             the public key with '.pub' as extension.
     * @param path Path to where the key files are stored
     * @param size RSA key size
     * @param use Usage for this new key
     */
    public static java.security.PrivateKey createStoreRSAKeyPair(String name, String path, int size, String use) {
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

