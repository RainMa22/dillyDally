package me.rainma22.dillydally.validation;

import java.net.URI;
import java.net.http.HttpRequest;

public class JoseHttpRequest {
    public static HttpRequest.Builder newBuilder(URI uri) {
        return HttpRequest.newBuilder(uri)
                .header("Content-Type", "application/jose+json");
    }
}
