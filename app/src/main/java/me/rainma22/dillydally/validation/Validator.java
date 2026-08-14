package me.rainma22.dillydally.validation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;

/**
 *
 */
public class Validator {

    private final HttpClient client = HttpClient.newHttpClient();
    private static final String LETS_ENCRYPT_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";
    private ResourceLocationResponse resourceLocations;
    private String nextNounce = null;

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

    private String newAccount(KeyPair kp) throws JoseException, IOException, InterruptedException, ExecutionException {
        if (resourceLocations.getMeta().externalAccountRequired) {
            throw new UnsupportedOperationException("External Account not supported");
        }
        if (nextNounce == null) {
            nextNounce = newNonce();
        }
        var jws = new JsonWebSignature();
        var jwk = JsonWebKey.Factory.newJwk(kp.getPublic());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        jws.setHeader("nonce", nextNounce);
        jws.setHeader("url", resourceLocations.getNewAccount());
        jws.setJwkHeader((PublicJsonWebKey) jwk);
        jws.setPayload(new JSONObject(
                Map.of("termsOfServiceAgreed", resourceLocations.getMeta().getTermsOfService() != null
                        ? true : null)
        ).toString());
        jws.setKey(kp.getPrivate());

        System.out.println(new JSONObject(jws.getHeaders().getFullHeaderAsJsonString())
                .toString(4)
        );
        System.out.println(new JSONObject(Map.of("termsOfServiceAgreed", resourceLocations.getMeta().getTermsOfService() != null
                ? true : null))
                .toString(4));
        var segments = jws.getCompactSerialization().split("[.]");
        System.out.println(segments[2]);
        var reqBody = new JSONObject(
                Map.of("protected", segments[0],
                        "payload", segments[1],
                        "signature", segments[2])
        ).toString();
        var req = HttpRequest.newBuilder(URI.create(resourceLocations.getNewAccount()))
                .header("Content-Type", "application/jose+json")
                .POST(HttpRequest.BodyPublishers.ofString(reqBody))
                .build();
        return client.sendAsync(req, BodyHandlers.ofString())
                .thenApply(res -> {
                    nextNounce = res.headers().firstValue("Replay-Nonce")
                            .orElse(null);
                    return res.body();
                }).get();
    }

    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException, JoseException, ExecutionException {
        System.out.println("Getting PATH from STAGING:");
        var validator = new Validator();
        System.out.println(new JSONObject(validator.resourceLocations).toString(4));
        System.out.println("Getting New Nonce:");
        var nonce = validator.newNonce();
        System.out.println(nonce);
        validator.nextNounce = nonce;
        System.out.println("Registering new User:");
        System.out.println(validator.newAccount(genUtils.generateKeyPair()));
    }

}
