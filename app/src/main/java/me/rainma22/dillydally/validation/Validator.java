package me.rainma22.dillydally.validation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import org.jose4j.jwk.JsonWebKey;
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
        private final ResourceLocationResponse resourceLocations;
        private String accountLocation = null;
        private String nextNonce = null;
        private KeyPair kp;
        private String orderLocation = null;

        public Validator(KeyPair kp) throws IOException, InterruptedException {
                this.kp = kp;
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

        private String getJSONofJWS(JsonWebSignature jws) throws JoseException {
                var segments = jws.getCompactSerialization().split("[.]");
                var reqBody = new JSONObject(
                                Map.of("protected", segments[0],
                                                "payload", segments[1],
                                                "signature", segments[2]))
                                .toString();
                return reqBody;
        }

        private String newAccount()
                        throws JoseException, IOException, InterruptedException, ExecutionException {
                if (resourceLocations.getMeta().externalAccountRequired) {
                        throw new UnsupportedOperationException("External Account not supported");
                }
                if (nextNonce == null) {
                        nextNonce = newNonce();
                }
                var jws = new JsonWebSignature();
                var jwk = JsonWebKey.Factory.newJwk(kp.getPublic());
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
                jws.setHeader("nonce", nextNonce);
                jws.setHeader("url", resourceLocations.getNewAccount());
                jws.setJwkHeader((PublicJsonWebKey) jwk);
                jws.setPayload(new JSONObject(
                                Map.of("termsOfServiceAgreed", true)).toString());
                jws.setKey(kp.getPrivate());
                var reqBody = getJSONofJWS(jws);
                var req = HttpRequest.newBuilder(URI.create(resourceLocations.getNewAccount()))
                                .header("Content-Type", "application/jose+json")
                                .POST(HttpRequest.BodyPublishers.ofString(reqBody))
                                .build();
                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApply(res -> {
                                        nextNonce = res.headers().firstValue("Replay-Nonce")
                                                        .orElse(null);
                                        accountLocation = res.headers().firstValue("Location").get();
                                        return res.body();
                                }).get();
        }

        public String newOrder() throws IOException, InterruptedException, JoseException, ExecutionException {
                if (nextNonce == null) {
                        nextNonce = newNonce();
                }
                if (accountLocation == null) {
                        newAccount();
                }

                var jws = new JsonWebSignature();
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
                jws.setHeader("kid", accountLocation);
                jws.setHeader("nonce", nextNonce);
                jws.setHeader("url", resourceLocations.getNewOrder());
                var payload = new JSONObject(
                                Map.of("identifiers", java.util.List.of(
                                                Map.of("type", "dns",
                                                                "value", "rainma.mooo.com"))));
                jws.setPayload(payload.toString());
                jws.setKey(kp.getPrivate());
                var reqBody = getJSONofJWS(jws);
                var req = HttpRequest.newBuilder(URI.create(resourceLocations.getNewOrder()))
                                .header("Content-Type", "application/jose+json")
                                .POST(BodyPublishers.ofString(reqBody))
                                .build();

                return client.sendAsync(req,
                                BodyHandlers.ofString())
                                .thenApply(res -> {
                                        nextNonce = res.headers().firstValue("Replay-Nonce")
                                                        .orElse(null);
                                        orderLocation = res.headers().firstValue("Location").get();
                                        return res.body();
                                }).get();
        }

        public String getCert() throws IOException, InterruptedException, JoseException, ExecutionException {
                String orderString = newOrder();
                return new JSONObject(JSONObject.fromJson(orderString, NewOrderResponse.class)).toString(4);
        }

        public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException,
                        JoseException, ExecutionException {
                System.out.println("Getting PATH from STAGING:");
                var validator = new Validator(GenUtils.generateKeyPair());
                System.out.println(new JSONObject(validator.resourceLocations).toString(4));
                System.out.println("Getting New Nonce:");
                var nonce = validator.newNonce();
                System.out.println(nonce);
                validator.nextNonce = nonce;
                System.out.println("Registering new User:");
                System.out.println(validator.newAccount());
                System.out.print("Account location: ");
                System.out.println(validator.accountLocation);
                System.out.println("requesting new order:");
                System.out.println(validator.getCert());
                System.out.print("Order location: ");
                System.out.println(validator.orderLocation);
        }

}
