package me.rainma22.dillydally.sslcert;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.util.concurrent.CompletableFuture;

public class ValidationHttpClient {
    private final HttpClient client = HttpClient.newHttpClient();
    private final ResourceLocationResponse resourceLocations;
    private String _nextNonce = null;

    public ValidationHttpClient(ResourceLocationResponse resourceLocations) {
        this.resourceLocations = resourceLocations;
    }

    public <T> HttpResponse<T> send(HttpRequest req, BodyHandler<T> handler) throws IOException, InterruptedException {
        return processNonce(client.send(req, handler));
    }

    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest req, BodyHandler<T> handler)
            throws IOException, InterruptedException {
        return client.sendAsync(req, handler)
                .thenApply(this::processNonce);
    }

    public String nextNonce() throws IOException, InterruptedException {
        if (_nextNonce != null) {
            String nonce = _nextNonce;
            _nextNonce = null;
            return nonce;
        }
        return client.send(HttpRequest.newBuilder(URI.create(resourceLocations.getNewNonce()))
                .HEAD()
                .build(),
                HttpResponse.BodyHandlers.ofByteArray())
                .headers()
                .firstValue("Replay-Nonce")
                .orElse(null);
    }

    private <T> HttpResponse<T> processNonce(HttpResponse<T> res) {
        _nextNonce = res.headers().firstValue("Replay-Nonce")
                .orElse(null);
        // System.out.println(res);
        // System.out.println(res.body());
        return res;
    }
}
