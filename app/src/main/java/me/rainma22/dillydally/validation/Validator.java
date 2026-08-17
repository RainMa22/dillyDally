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
import org.jose4j.jws.AlgorithmIdentifiers;
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

        private <T> HttpResponse<T> processNonce(HttpResponse<T> res) {
                nextNonce = res.headers().firstValue("Replay-Nonce")
                                .orElse(null);
                return res;
        }

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

        private String JSONStringof(ACMEJsonWebSignature sig) throws JoseException {
                return sig.toJson().toString(4);
        }

        private String newAccount()
                        throws JoseException, IOException, InterruptedException, ExecutionException {
                if (resourceLocations.getMeta().externalAccountRequired) {
                        throw new UnsupportedOperationException("External Account not supported");
                }
                if (nextNonce == null) {
                        nextNonce = newNonce();
                }
                var jwk = JsonWebKey.Factory.newJwk(kp.getPublic());
                var jws = new ACMEJsonWebSignature(jwk, nextNonce, resourceLocations.getNewAccount(), kp.getPrivate());
                jws.setPayload(new JSONObject(
                                Map.of("termsOfServiceAgreed", true)).toString());
                var reqBody = JSONStringof(jws);
                var req = JoseHttpRequest.newBuilder(URI.create(resourceLocations.getNewAccount()))
                                .POST(HttpRequest.BodyPublishers.ofString(reqBody))
                                .build();
                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce)
                                .thenApply(res -> {
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

                var jws = new ACMEJsonWebSignature(accountLocation, nextNonce, resourceLocations.getNewOrder(),
                                kp.getPrivate());
                var payload = new JSONObject(
                                Map.of("identifiers", java.util.List.of(
                                                Map.of("type", "dns",
                                                                "value", "rainma.mooo.com"))));
                jws.setPayload(payload.toString());
                var reqBody = JSONStringof(jws);
                var req = JoseHttpRequest.newBuilder(URI.create(resourceLocations.getNewOrder()))
                                .POST(BodyPublishers.ofString(reqBody))
                                .build();

                return client.sendAsync(req,
                                BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce)
                                .thenApply(res -> {
                                        orderLocation = res.headers().firstValue("Location").get();
                                        return res.body();
                                }).get();
        }

        public String getAuthChallenges(String authString)
                        throws JoseException, InterruptedException, ExecutionException {
                var jws = new ACMEJsonWebSignature(accountLocation, nextNonce, authString, kp.getPrivate());
                var req = JoseHttpRequest.newBuilder(URI.create(authString))
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();
                return client.sendAsync(req,
                                BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce)
                                .thenApply(res -> {
                                        return res.body();
                                })
                                .get();
        }

        public String getCert() throws IOException, InterruptedException, JoseException, ExecutionException {
                System.out.println("requesting new order:");

                String orderString = newOrder();
                var orderRes = JSONObject.fromJson(orderString, NewOrderResponse.class);
                System.out.println(new JSONObject(orderRes).toString(4));
                System.out.print("Order location: ");
                System.out.println(orderLocation);
                System.out.println("Getting Auth Challenges:");
                for (var auth : orderRes.getAuthorizations()) {
                        System.out.println(auth + ": " + new JSONObject(getAuthChallenges(auth)).toString(4));
                }
                return "";
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
                System.out.println("Getting Cert:");
                validator.getCert();
        }

}
