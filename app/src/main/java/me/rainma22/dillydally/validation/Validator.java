package me.rainma22.dillydally.validation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.operator.OperatorCreationException;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.HashUtil;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;

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
        private ConfBean conf;

        private <T> HttpResponse<T> processNonce(HttpResponse<T> res) {
                nextNonce = res.headers().firstValue("Replay-Nonce")
                                .orElse(null);
                return res;
        }

        public Validator(ConfBean conf, KeyPair kp) throws IOException, InterruptedException {
                this.conf = conf;
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
                var identifiers = conf.getDomains()
                                .stream()
                                .map(str -> {
                                        var res = new OrderIdentifier();
                                        res.setType("dns");
                                        res.setValue(str);
                                        return res;
                                }).toList();
                var payload = new JSONObject(
                                Map.of("identifiers", identifiers));
                jws.setPayload(payload.toString());
                var reqBody = JSONStringof(jws);
                var req = JoseHttpRequest.newBuilder(URI.create(resourceLocations.getNewOrder()))
                                .POST(BodyPublishers.ofString(reqBody))
                                .build();

                return client.sendAsync(req,
                                BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce)
                                .thenApply(res -> {
                                        orderLocation = res.headers().firstValue("Location").orElse(null);
                                        return res.body();
                                }).get();
        }

        public AuthChallengeResponse getAuthChallenge(String authString)
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
                                .thenApply(str -> JSONObject.fromJson(str, AuthChallengeResponse.class))
                                .get();
        }

        public CompletableFuture<HttpResponse<String>> tryCompleteChallenge(String challengeUrl)
                        throws IOException, InterruptedException, JoseException {
                URI challengeUri = URI.create(challengeUrl);
                if (nextNonce == null)
                        newNonce();
                var jws = new ACMEJsonWebSignature(accountLocation, nextNonce, challengeUrl,
                                kp.getPrivate());
                jws.setPayload("{}");
                var req = JoseHttpRequest.newBuilder(challengeUri)
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();

                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce);
        }

        public CompletableFuture<HttpResponse<String>> finalizeRequest(String finalizeUrl)
                        throws IOException, InterruptedException,
                        OperatorCreationException, NoSuchAlgorithmException, JoseException, ExecutionException {
                URI finalizeUri = URI.create(finalizeUrl);
                if (nextNonce == null) {
                        newNonce();
                }

                var jws = new ACMEJsonWebSignature(accountLocation, nextNonce, finalizeUrl, kp.getPrivate());
                jws.setPayload(new JSONObject(
                                Map.of("CSR", Base64Url.encode(GenUtils.genCSR(conf).getEncoded()))).toString());

                var req = JoseHttpRequest.newBuilder(finalizeUri)
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();
                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce);
        }

        public CompletableFuture<HttpResponse<String>> getOrder(String orderUrl)
                        throws IOException, InterruptedException, JoseException {
                URI orderUri = URI.create(orderUrl);
                if (nextNonce == null)
                        newNonce();
                var jws = new ACMEJsonWebSignature(accountLocation, nextNonce, orderUrl, kp.getPrivate());
                var req = JoseHttpRequest.newBuilder(orderUri)
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();
                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce);
        }

        public String getCert() throws IOException, InterruptedException, JoseException, ExecutionException,
                        OperatorCreationException, NoSuchAlgorithmException {
                System.out.println("requesting new order:");

                String orderString = newOrder();
                var orderRes = JSONObject.fromJson(orderString, NewOrderResponse.class);
                System.out.println(new JSONObject(orderRes).toString(4));
                System.out.print("Order location: ");
                System.out.println(orderLocation);
                System.out.println("Getting Auth Challenges:");
                Map<String, AuthChallengeResponse> responses = new HashMap<>();
                for (var auth : orderRes.getAuthorizations()) {
                        var res = getAuthChallenge(auth);
                        System.out.println(auth + ": " + new JSONObject(res).toString(4));
                        // select http-01 challenges
                        var http01Challenge = res.getChallenges().stream()
                                        .filter(c -> c.getType().equalsIgnoreCase("http-01"))
                                        .findAny()
                                        .orElse(null);
                        if (http01Challenge == null) {
                                throw new UnsupportedOperationException("only http-01 challenges supported for now");
                        }
                        System.out.println(new JSONObject(http01Challenge).toString(4));
                        if (!conf.getHttpChallengeConf().getType().equalsIgnoreCase("file")) {
                                System.out.printf("would put %s at http://%s/.well-known/acme-challenge/%s \n",
                                                http01Challenge.getToken(),
                                                res.getIdentifier().getValue(), http01Challenge.getToken());
                                throw new UnsupportedOperationException(
                                                "unsupported challenge type configured: "
                                                                + conf.getHttpChallengeConf().getType());
                        } else {
                                var httpConf = conf.getHttpChallengeConf();
                                var challengeFolderPath = Path.of(httpConf.getPathToWebRootDir(), ".well-known",
                                                "acme-challenge");
                                Files.createDirectories(challengeFolderPath);
                                var challengeFilePath = challengeFolderPath.resolve(http01Challenge.getToken());
                                var thumbprint = Base64Url.encode(JsonWebKey.Factory.newJwk(kp.getPublic())
                                                .calculateThumbprint(HashUtil.SHA_256)).replaceAll("=", "");

                                Files.createFile(challengeFilePath);
                                Files.writeString(challengeFilePath, http01Challenge.getToken() + "." + thumbprint);
                                System.out.printf("finished putting %s at %s/.well-known/acme-challenge/%s \n",
                                                http01Challenge.getToken(),
                                                conf.getHttpChallengeConf().getPathToWebRootDir(),
                                                http01Challenge.getToken());
                                var url = String.format(
                                                "http://%s/.well-known/acme-challenge/%s",
                                                res.getIdentifier().getValue(), http01Challenge.getToken());
                                System.out.printf("Checking if %s is accesible now...", url);
                                var accesible = Utils.webAccessible(URI.create(url));
                                System.out.println(accesible);

                                var challengeRes = tryCompleteChallenge(http01Challenge.getUrl());
                                challengeRes.thenApply(r -> r.body())
                                                .thenApply(str -> new JSONObject(str))
                                                .thenApply(obj -> obj.toString(4))
                                                .thenAccept(System.out::println)
                                                .get();
                                AtomicLong waitTimeSec = new AtomicLong(0);
                                while (waitTimeSec.get() != -1) {
                                        System.out.printf("Waiting for validation, retrying in %d seconds... \n",
                                                        waitTimeSec.get());
                                        Thread.sleep(Duration.ofSeconds(waitTimeSec.get()));
                                        if (nextNonce == null)
                                                newNonce();
                                        var authStatus = client.sendAsync(
                                                        JoseHttpRequest.newBuilder(URI.create(auth))
                                                                        .POST(BodyPublishers.ofString(
                                                                                        JSONStringof(new ACMEJsonWebSignature(
                                                                                                        accountLocation,
                                                                                                        nextNonce, auth,
                                                                                                        kp.getPrivate()))))
                                                                        .build(),
                                                        BodyHandlers.ofString())
                                                        .thenApplyAsync(this::processNonce)
                                                        .thenApplyAsync(r -> {
                                                                String retryAfter = r.headers()
                                                                                .firstValue("Retry-After").orElse("1");
                                                                try {
                                                                        waitTimeSec.set(Long
                                                                                        .parseLong(retryAfter));
                                                                } catch (NumberFormatException nfe) {
                                                                        waitTimeSec.set(1);
                                                                }
                                                                return r;

                                                        })
                                                        .thenApply(r -> r.body())
                                                        .get();
                                        AuthChallengeResponse newResponse = JSONObject.fromJson(authStatus,
                                                        AuthChallengeResponse.class);
                                        if (newResponse.getStatus().equals(ResponseConstants.VALID)) {
                                                responses.put(auth, newResponse);
                                                break;
                                        }
                                }
                        }
                        responses.forEach((k, v) -> {
                                System.out.printf("%s: %s \n\n", k, new JSONObject(v).toString(4));
                        });
                        AtomicLong waitTimeSec = new AtomicLong(0);
                        System.out.println("finalizing: ");
                        waitTimeSec.set(0);
                        while (waitTimeSec.get() != -1) {
                                Thread.sleep(Duration.ofSeconds(waitTimeSec.get()));
                                var finalizeRes = finalizeRequest(orderRes.getFinalize());
                                finalizeRes.thenAccept((r) -> {
                                        JSONObject finalJson = new JSONObject(r.body());
                                        var status = finalJson.optString("status", "");
                                        if (status.equals(ResponseConstants.PROCESSING)) {
                                                System.out.print("Waiting for the server to finish finalizing... \n");
                                                try {
                                                        waitTimeSec.set(r.headers().firstValueAsLong("Retry-After")
                                                                        .orElse(1));
                                                } catch (NumberFormatException nfe) {
                                                        waitTimeSec.set(1);
                                                }
                                        } else {
                                                System.out.printf("STATUS = %s", status);
                                                System.out.println(finalJson.toString(4));
                                                waitTimeSec.set(-1);
                                        }
                                }).get();
                        }
                        waitTimeSec.set(0);
                        while (waitTimeSec.get() != -1) {
                                Thread.sleep(Duration.ofSeconds(waitTimeSec.get()));
                                var orderRes2 = getOrder(orderLocation);
                                orderRes2.thenAccept((r) -> {
                                        JSONObject orderJson = new JSONObject(r.body());
                                        var status = orderJson.optString("status", "");
                                        if (!status.equals(ResponseConstants.VALID)) {
                                                System.out.print("Waiting for the order rto be valid... \n");
                                                try {
                                                        waitTimeSec.set(r.headers().firstValueAsLong("Retry-After")
                                                                        .orElse(1));
                                                } catch (NumberFormatException nfe) {
                                                        waitTimeSec.set(1);
                                                }
                                        } else {
                                                System.out.printf("STATUS = %s", status);
                                                System.out.println(orderJson.toString(4));
                                                waitTimeSec.set(-1);
                                        }
                                }).get();
                        }
                }

                return "";
        }

        public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException,
                        JoseException, ExecutionException, OperatorCreationException {
                final Path configDirPath = Path.of("config");
                final Path configJson = configDirPath.resolve("config.json");
                try {
                        Files.createDirectories(configDirPath);
                        Files.createFile(configJson);
                } catch (Exception e) {
                        // ignored
                }
                ConfBean config = new ConfBean();
                try {
                        config = JSONObject.fromJson(Files.readString(configJson), ConfBean.class);
                        Files.writeString(configJson, new JSONObject(config).toString(4), StandardCharsets.UTF_8);
                } catch (JSONException je) {
                        System.out.println("failed to load configuration json, default will be used instead");
                        je.printStackTrace();
                }
                System.out.println("Getting PATH from STAGING:");
                var validator = new Validator(config, GenUtils.generateKeyPair());
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
