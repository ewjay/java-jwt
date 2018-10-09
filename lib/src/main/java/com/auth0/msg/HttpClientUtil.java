package com.auth0.msg;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

public abstract class HttpClientUtil {
    enum HttpClientSingleton {
        INSTANCE;

        CloseableHttpClient httpClient;

        HttpClientSingleton() {
            httpClient = HttpClients.createDefault();
        }

        public CloseableHttpClient instance() {
            return httpClient;
        }

        public void setClient(CloseableHttpClient httpClient) {
            this.httpClient = httpClient;
        }
    }

    static class HttpFetchResponse {
        private int statusCode;
        private String contentType;
        private String body;

        public HttpFetchResponse(int statusCode, String contentType, String body) {
            this.statusCode = statusCode;
            this.contentType = contentType;
            this.body = body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getContentType() {
            return contentType;
        }

        public String getBody() {
            return body;
        }
    }

    public static HttpFetchResponse fetchUri(HttpUriRequest httpUriRequest, HttpContext httpContext) throws IOException{
        CloseableHttpClient  httpClient = instance();
        CloseableHttpResponse httpResponse = null;
        try {
            httpResponse = httpClient.execute(httpUriRequest, httpContext);
            HttpEntity httpEntity = httpResponse.getEntity();
            int statusCode = httpResponse.getStatusLine().getStatusCode();
            String contentType = httpResponse.getFirstHeader("Content-Type").getValue();
            String body = EntityUtils.toString(httpEntity);
            return new HttpFetchResponse(statusCode, contentType, body);
        }
        finally{
            if(httpResponse != null) {
                httpResponse.close();
            }
        }
    }

    public static CloseableHttpClient instance() {
        return HttpClientSingleton.INSTANCE.instance();
    }

    public static void setClient(CloseableHttpClient client) {
        HttpClientSingleton.INSTANCE.setClient(client);
    }
}
