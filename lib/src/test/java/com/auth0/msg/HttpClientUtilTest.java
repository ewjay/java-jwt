package com.auth0.msg;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.hamcrest.core.IsEqual;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class HttpClientUtilTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testDefaultClient() throws Exception {

        String source = "https://connect.openid4.us:5443/phpOp/.well-known/openid-configuration";

        CloseableHttpClient httpClient = null;
        CloseableHttpResponse response = null;

        try {

            httpClient = HttpClientUtil.instance();
            response = httpClient.execute(new HttpGet(source));

            int status = response.getStatusLine().getStatusCode();

            if(status == 200) {
                HttpEntity httpEntity = response.getEntity();
                Header[] headers = response.getAllHeaders();
                for(Header header : headers) {
                    System.out.printf("%s : %s\n", header.getName(), header.getValue());
                }
                System.out.println(EntityUtils.toString(response.getEntity()));
            }
            EntityUtils.consume(response.getEntity());
        } catch(IOException e) {
            System.out.println(e);

        }finally {
            if(response != null) {
                response.close();
            }
        }


    }

    public CloseableHttpClient createHttpClient_AcceptsUntrustedCerts()  throws  Exception{
        HttpClientBuilder b = HttpClientBuilder.create();

        // setup a Trust Strategy that allows all certificates.
        //
        SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
            public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                return true;
            }
        }).build();
        b.setSslcontext( sslContext);

        // don't check Hostnames, either.
        //      -- use SSLConnectionSocketFactory.getDefaultHostnameVerifier(), if you don't want to weaken
        HostnameVerifier hostnameVerifier = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;

        // here's the special part:
        //      -- need to create an SSL Socket Factory, to use our weakened "trust strategy";
        //      -- and create a Registry, to register it.
        //
        SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(sslContext, hostnameVerifier);
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
            .register("http", PlainConnectionSocketFactory.getSocketFactory())
            .register("https", sslSocketFactory)
            .build();

        // now, we create connection-manager using our Registry.
        //      -- allows multi-threaded use
        PoolingHttpClientConnectionManager connMgr = new PoolingHttpClientConnectionManager( socketFactoryRegistry);
        b.setConnectionManager( connMgr);

        // finally, build the HttpClient;
        //      -- done!
        return b.build();
    }

    @Ignore
    public void testNoSSLVerifyClient() throws Exception {
        CloseableHttpClient httpClient = HttpClientUtil.instance();

        System.setProperty("jsse.enableSNIExtension", "false");

        String source = "https://oidc.openid4.us:5443/phpOp/.well-known/openid-configuration";

//        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null,
//            new TrustSelfSignedStrategy()).build();

        SSLContext sslcontext = SSLContexts.custom().loadTrustMaterial(null,
            new TrustStrategy() {
                @Override
                public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    return true;
                }
            }).build();

// Allow TLSv1 protocol only, use NoopHostnameVerifier to trust self-singed cert
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext,
            null, null, new NoopHostnameVerifier());

//        CloseableHttpClient noTrustClient = HttpClients
//            .custom()
//            .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
//            .build();
        CloseableHttpClient noTrustClient = HttpClients
            .custom()
            .setSSLSocketFactory(sslsf)
            .build();

        HttpClientUtil.setClient(noTrustClient);

        try {

            httpClient = noTrustClient;
            CloseableHttpResponse response = httpClient.execute(new HttpGet(source));

            int status = response.getStatusLine().getStatusCode();

            if(status == 200) {
                HttpEntity httpEntity = response.getEntity();
                Header[] headers = response.getAllHeaders();
                for(Header header : headers) {
                    System.out.printf("%s : %s\n", header.getName(), header.getValue());
                }
                System.out.println(EntityUtils.toString(response.getEntity()));
            }
        } catch(IOException e) {
            System.out.println(e);
            throw e;

        }finally {
            httpClient.close();
        }


    }

    @Ignore
    public void givenIgnoringCertificates_whenHttpsUrlIsConsumed_thenCorrect()
        throws Exception {
        SSLContext sslContext = new SSLContextBuilder()
            .loadTrustMaterial(null, (certificate, authType) -> true).build();

        CloseableHttpClient client = HttpClients.custom()
            .setSSLContext(sslContext)
            .setSSLHostnameVerifier(new NoopHostnameVerifier())
            .build();
        HttpGet httpGet = new HttpGet("https://oidc.openid4.us:5443/phpOp/.well-known/openid-configuration");
        httpGet.setHeader("Accept", "application/xml");

        HttpResponse response = client.execute(httpGet);
        Assert.assertThat(response.getStatusLine().getStatusCode(), IsEqual.equalTo(200));
    }

    /**
     * A thread that performs a GET.
     */
    static class GetThread extends Thread {

        private final CloseableHttpClient httpClient;
        private final HttpContext context;
        private final HttpGet httpget;
        private final int id;

        public GetThread(CloseableHttpClient httpClient, HttpGet httpget, int id) {
            this.httpClient = httpClient;
            this.context = new BasicHttpContext();
            this.httpget = httpget;
            this.id = id;
        }

        /**
         * Executes the GetMethod and prints some status information.
         */
        @Override
        public void run() {
            try {
                System.out.println(id + " - " + httpget.getURI());
                HttpClientUtil.HttpFetchResponse response = HttpClientUtil.fetchUri(httpget, context);
                System.out.printf("%d - %s : %d : %s\n", id, httpget.getURI().toString(), response.getStatusCode(), response.getContentType());


            } catch (Exception e) {
                System.out.println(id + " - error: " + e);
            }
        }

    }

    public void connectionThreadHelper(CloseableHttpClient httpClient) throws IOException {

        HttpClientUtil.setClient(httpClient);
        try {
            // create an array of URIs to perform GETs on
            String[] urisToGet = {
                "http://hc.apache.org/",
                "http://hc.apache.org/httpcomponents-core-ga/",
                "http://hc.apache.org/httpcomponents-client-ga/",
                "https://www.yahoo.com",
                "https://www.google.com",
                "https://www.bing.com",
                "https://www.microsoft.com"
            };

            final int iterations = 100;
            GetThread[] threads = new GetThread[iterations];

            for(int num = 0; num < iterations; num++) {
                HttpGet httpget = new HttpGet(urisToGet[num % urisToGet.length]);
                threads[num] = new GetThread(HttpClientUtil.instance(), httpget, num + 1);
            }
            for (int j = 0; j < threads.length; j++) {
                threads[j].start();
            }
            // join the threads
            for (int j = 0; j < threads.length; j++) {
                threads[j].join();
            }

        } catch(Exception e) {
            System.out.println(e.toString());
        }
    }


    @Test
    public void testClientWithThreads() {
        CloseableHttpClient httpClient = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.custom()
                .setCookieSpec(CookieSpecs.STANDARD).build())
            .setMaxConnTotal(100)
            .build();


        CloseableHttpClient defaultClient = HttpClients.createDefault();

        try {
            connectionThreadHelper(httpClient);
            connectionThreadHelper(defaultClient);
        } catch(IOException e) {
            System.out.println(e.toString());
        }

    }





}
