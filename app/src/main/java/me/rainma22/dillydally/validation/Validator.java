package me.rainma22.dillydally.validation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;

/**
 *
 */
public class Validator {

    private final HttpClient client = HttpClient.newHttpClient();
    private static final String LETS_ENCRYPT_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
    private ResourceLocationResponse resourceLocations;
    String nextNounce = null;

    public Validator() throws IOException, InterruptedException {
        resourceLocations = new JSONObject(
                client.send(HttpRequest.newBuilder(URI.create(LETS_ENCRYPT_STAGING_URL))
                        .GET()
                        .build(),
                        HttpResponse.BodyHandlers.ofString())
                        .body())
                .fromJson(ResourceLocationResponse.class);
    }

    private String newNonce() throws IOException, InterruptedException {
        return client.send(HttpRequest.newBuilder(URI.create(resourceLocations.getNewNonce()))
                .HEAD()
                .build(),
                HttpResponse.BodyHandlers.ofByteArray())
                .headers()
                .firstValue("Replay-Nonce")
                .orElse(null);
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        System.out.println("Getting PATH from STAGING:");
        var validator = new Validator();
        System.out.println(new JSONObject(validator.resourceLocations).toString(4));
        System.out.println("Getting New Nonce:");
        System.out.println(validator.newNonce());

    }

}
