package com.auth0.msg;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public class KeyUtilsTest {
    private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";
    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
    private static final String PUBLIC_CERT_FILE = "src/test/resources/cert.pem";
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testWriteKeyFiles() throws Exception {
        int keySize = 2048;
        KeyPair keyPair = RSAKey.generateRSAKeyPair(keySize);
        Assert.assertNotNull(keyPair);
        Assert.assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
        Assert.assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        Assert.assertEquals(rsaPrivateKey.getModulus().bitLength(), keySize);
        Assert.assertEquals(rsaPublicKey.getModulus().bitLength(), keySize);
        Path currentRelativePath = Paths.get("");
        String curDir = currentRelativePath.toAbsolutePath().toString();
        String filename = "testkey";
        String privateFilename = curDir + File.separator + filename;
        String publicFilename = curDir + File.separator + filename + ".pub";
        KeyUtils.writeRSAPemFile(privateFilename, rsaPrivateKey);
        KeyUtils.writeRSAPemFile(publicFilename, rsaPublicKey);
        File publicFile = new File(publicFilename);
        Assert.assertTrue(publicFile.exists());
        File privateFile = new File(privateFilename);
        Assert.assertTrue(privateFile.exists());
        PublicKey publicKeyIn = KeyUtils.getRSAPublicKeyFromFile(publicFilename);
        Assert.assertNotNull(publicKeyIn);
        Assert.assertTrue(publicKeyIn instanceof RSAPublicKey);
        Assert.assertEquals(((RSAPublicKey)publicKeyIn).getModulus().bitLength(), keySize);
        PrivateKey privateKeyIn = KeyUtils.getRSAPrivateKeyFromFile(privateFilename);
        Assert.assertNotNull(privateKeyIn);
        Assert.assertTrue(privateKeyIn instanceof RSAPrivateKey);
        Assert.assertEquals(((RSAPrivateKey)privateKeyIn).getModulus().bitLength(), keySize);
        privateFile.delete();
        publicFile.delete();
    }

    @Test
    public void testReadKeyFiles() throws IOException {
        Key publicKey = KeyUtils.getRSAKeyFromFile(PUBLIC_KEY_FILE);
        Assert.assertNotNull(publicKey);
        Assert.assertTrue(publicKey instanceof RSAPublicKey);

        Key privateKey = KeyUtils.getRSAKeyFromFile(PRIVATE_KEY_FILE);
        Assert.assertNotNull(privateKey);
        Assert.assertTrue(privateKey instanceof RSAPrivateKey);
    }

    @Test
    public void testReadPrivateKeyFile() throws IOException {
        PrivateKey privateKey = KeyUtils.getRSAPrivateKeyFromFile(PRIVATE_KEY_FILE);
        Assert.assertNotNull(privateKey);
        Assert.assertTrue(privateKey instanceof RSAPrivateKey);
   }

    @Test
    public void testReadPublicKeyFiles() throws IOException {
        PublicKey publicKey = KeyUtils.getRSAPublicKeyFromFile(PUBLIC_KEY_FILE);
        Assert.assertNotNull(publicKey);
        Assert.assertTrue(publicKey instanceof RSAPublicKey);
    }

    @Test
    public void testGetRSAKeyFromCertFile() throws IOException, CertificateException {
        PublicKey rsaPublicKey = KeyUtils.getRSAKeyFromCertFile(PUBLIC_CERT_FILE);
        Assert.assertNotNull(rsaPublicKey);
        Assert.assertTrue(rsaPublicKey instanceof RSAPublicKey);
    }
}
