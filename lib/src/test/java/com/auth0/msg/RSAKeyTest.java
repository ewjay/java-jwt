package com.auth0.msg;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSAKeyTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testGenRSAKeys() {
        int[] keySizes = new int[] {1024, 2048, 3072, 4096};
        for(int keySize : keySizes) {
            KeyPair keyPair = RSAKey.generateRSAKeyPair(keySize);
            Assert.assertNotNull(keyPair);
            Assert.assertTrue(keyPair.getPrivate() instanceof RSAPrivateKey);
            Assert.assertTrue(keyPair.getPublic() instanceof RSAPublicKey);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            Assert.assertEquals(rsaPrivateKey.getModulus().bitLength(), keySize);
            Assert.assertEquals(rsaPublicKey.getModulus().bitLength(), keySize);
        }
    }


}
