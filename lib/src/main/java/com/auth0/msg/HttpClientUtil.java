package com.auth0.msg;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public abstract class HttpClientUtil {
    enum HttpClientSingleton {
        INSTANCE;

        CloseableHttpClient httpClient;

        public CloseableHttpClient instance() {
            if(httpClient == null) {
                httpClient = HttpClients.createDefault();
            }
            return httpClient;
        }

        public void setClient(CloseableHttpClient httpClient) {
            this.httpClient = httpClient;
        }
    }

    public static CloseableHttpClient instance() {
        return HttpClientSingleton.INSTANCE.instance();
    }

    public static void setClient(CloseableHttpClient client) {
        HttpClientSingleton.INSTANCE.setClient(client);
    }
}
