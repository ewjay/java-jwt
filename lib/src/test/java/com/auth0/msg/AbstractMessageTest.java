package com.auth0.msg;

import com.auth0.jwt.impl.PayloadSerializer;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;


import java.io.StringWriter;
import java.util.HashMap;

import static org.hamcrest.CoreMatchers.is;

public class AbstractMessageTest {
    private StringWriter writer;
    private PayloadSerializer serializer;
    private JsonGenerator jsonGenerator;
    private SerializerProvider serializerProvider;

    @Before
    public void setUp() throws Exception {
        writer = new StringWriter();
        serializer = new PayloadSerializer();
        jsonGenerator = new JsonFactory().createGenerator(writer);
        ObjectMapper mapper = new ObjectMapper();
        jsonGenerator.setCodec(mapper);
        serializerProvider = mapper.getSerializerProvider();
    }
    @Test
    public void testToUrlEncoded() throws Exception {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("GRAND_TYPE", "refresh_token");

        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        String pcrUrlEncoded = pcr.toUrlEncoded();
    }

    @Test
    public void testToJson() throws Exception {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("GRANT_TYPE", "refresh_token");

        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        String pcrJson = pcr.toJson();
        String testJson = "{\"claims\":{\"GRANT_TYPE\":\"refresh_token\"},\"error\":null}";
        assertThat(pcrJson, is(testJson));
    }

    @Test
    public void testFromJson() throws Exception {
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("GRANT_TYPE", "refresh_token");
        String testJson = "{\"claims\":{\"GRANT_TYPE\":\"refresh_token\"},\"error\":null}";
        ProviderConfigurationResponse pcr = new ProviderConfigurationResponse(claims);
        pcr.fromJson(testJson);
        assertEquals(pcr.getClaims(),claims);
// TODO
//        String jsonPCR = "{\"claims\":{\"GRANT_TYPE\":\"refresh_token\"},\"error\":null}";
//        ProviderConfigurationResponse pcrOut = new ProviderConfigurationResponse();
//        pcrOut.fromJson(jsonPCR);
//        assertThat(pcrOut.getClaims(), CoreMatchers.<Map<Claim, Object>>is(claims));
//        assertThat(pcrOut.getError(), is(nullValue()));
    }
}