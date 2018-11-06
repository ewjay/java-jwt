package com.auth0.msg;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

/**
 * Manages a shared CloseableHttpClient instance for fetching HTTP requests
 * If will ue the default instance if none is set. If the client requires specific options
 * (e.g. ignore SSL errors), the calling application is responsbile for creating the client
 * instance with the options and tracked via this class.
 */
public abstract class HttpClientUtil {

    /**
     * Singleton class for the shared HTTP client instance
     */
    enum HttpClientSingleton {
        INSTANCE;

        CloseableHttpClient httpClient;

        HttpClientSingleton() {
            httpClient = HttpClients.createDefault();
        }

        /**
         * Gets the current CloseableHttpClient instance
         * @return current
         */
        public CloseableHttpClient instance() {
            return httpClient;
        }

        /**
         * Sets the shareable client instance to the specified instance
         * @param httpClient HTTP client instance to
         */
        public void setClient(CloseableHttpClient httpClient) {
            this.httpClient = httpClient;
        }
    }

    /**
     * Class for encapsulating the HTTP response code, content-type header, and body
     */
    public static class HttpFetchResponse {
        private int statusCode;
        private String contentType;
        private String body;

        /**
         * Constructor for creating a HTTPFetchResponse
         * @param statusCode the HTTP status code
         * @param contentType the first HTTP content-type header in the HTTP response
         * @param body the HTTP response body text
         */
        public HttpFetchResponse(int statusCode, String contentType, String body) {
            this.statusCode = statusCode;
            this.contentType = contentType;
            this.body = body;
        }

        /**
         * Gets the HTTP status code
         * @return
         */
        public int getStatusCode() {
            return statusCode;
        }

        /***
         * Gets the HTTP content-type header, can be null
          * @return string of the HTTP content-type response hreader
         */
        public String getContentType() {
            return contentType;
        }

        /**
         * Gets the HTTP response text as a string
         * @return the HTTP response's body as a string
         */
        public String getBody() {
            return body;
        }
    }

    /***
     *
     * @param httpUriRequest
     * @param httpContext
     * @return
     * @throws IOException
     */
    public static HttpFetchResponse fetchUri(HttpUriRequest httpUriRequest, HttpContext httpContext)
        throws IOException{
        CloseableHttpClient  httpClient = instance();
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpUriRequest, httpContext);
            HttpEntity httpEntity = httpResponse.getEntity();
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            Header contentTypeHeader = httpResponse.getFirstHeader("Content-Type");
            String body = EntityUtils.toString(httpEntity);
            return new HttpFetchResponse(statusCode,
                contentTypeHeader == null ? null : contentTypeHeader.getValue(), body);
        }
        finally{
            if(httpResponse != null) {
                httpResponse.close();
            }
        }
    }

    /**
     * Gets the current shared HTTP client instance
     * @return the current shared HTTP client instance
     */
    public static CloseableHttpClient instance() {
        return HttpClientSingleton.INSTANCE.instance();
    }

    /***
     * Sets the shared client to the specified instance. Application is responsible for setting
     * desired client options.
     * @param client The client instance to be shared withing the application for HTTP fetches
     */
    public static void setClient(CloseableHttpClient client) {
        HttpClientSingleton.INSTANCE.setClient(client);
    }
}
