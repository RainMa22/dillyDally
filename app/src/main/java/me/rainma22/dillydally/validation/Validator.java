package me.rainma22.dillydally.validation;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.StringReader;
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
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64.Encoder;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.OperatorCreationException;
import org.json.JSONException;
import org.json.JSONObject;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.security.Jwks;
import me.rainma22.dillydally.conf.ConfBean;

/**
 *
 */
public class Validator {

        private final HttpClient client = HttpClient.newHttpClient();
        private final Encoder Base64Url = Base64.getUrlEncoder();
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
                                client.send(HttpRequest.newBuilder(URI.create(conf.getServerUrl()))
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

        private String JSONStringof(JwtBuilder sig) {
                return ACMEJWS.toJson(sig).toString(4);
        }

        private String newAccount()
                        throws IOException, InterruptedException, ExecutionException {
                if (resourceLocations.getMeta().externalAccountRequired) {
                        throw new UnsupportedOperationException("External Account not supported");
                }
                if (nextNonce == null) {
                        nextNonce = newNonce();
                }
                var jwk = Jwks.builder().key(kp.getPublic()).build();
                var jws = ACMEJWS.withJWK(jwk, nextNonce, resourceLocations.getNewAccount(), kp.getPrivate());
                jws.content(new JSONObject(
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

        public String newOrder() throws IOException, InterruptedException, ExecutionException {
                
                var jws = ACMEJWS.withAccountLocation(accountLocation, nextNonce, resourceLocations.getNewOrder(),
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
                jws.content(payload.toString());
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
                        throws InterruptedException, ExecutionException {
                var jws = ACMEJWS.withAccountLocation(accountLocation, nextNonce, authString, kp.getPrivate());
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
                        throws IOException, InterruptedException {
                URI challengeUri = URI.create(challengeUrl);
                if (nextNonce == null)
                        newNonce();
                var jws = ACMEJWS.withAccountLocation(accountLocation, nextNonce, challengeUrl,
                                kp.getPrivate());
                jws.content("{}");
                var req = JoseHttpRequest.newBuilder(challengeUri)
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();

                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce);
        }

        public CompletableFuture<HttpResponse<String>> finalizeRequest(String finalizeUrl, KeyPair sslKeyPair)
                        throws IOException, InterruptedException,
                        OperatorCreationException, NoSuchAlgorithmException, ExecutionException {
                URI finalizeUri = URI.create(finalizeUrl);
                if (nextNonce == null) {
                        newNonce();
                }

                var jws = ACMEJWS.withAccountLocation(accountLocation, nextNonce, finalizeUrl, kp.getPrivate());
                jws.content(new JSONObject(
                                Map.of("CSR", Base64Url.encodeToString(GenUtils.genCSR(conf, sslKeyPair).getEncoded())))
                                .toString());

                var req = JoseHttpRequest.newBuilder(finalizeUri)
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();
                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce);
        }

        public CompletableFuture<HttpResponse<String>> getOrder(String orderUrl)
                        throws IOException, InterruptedException {
                URI orderUri = URI.create(orderUrl);
                if (nextNonce == null)
                        newNonce();
                var jws = ACMEJWS.withAccountLocation(accountLocation, nextNonce, orderUrl, kp.getPrivate());
                var req = JoseHttpRequest.newBuilder(orderUri)
                                .POST(BodyPublishers.ofString(JSONStringof(jws)))
                                .build();
                return client.sendAsync(req, BodyHandlers.ofString())
                                .thenApplyAsync(this::processNonce);
        }

        public String getCert(KeyPair sslKeyPair)
                        throws IOException, InterruptedException, ExecutionException,
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
                                var thumbprint = Jwks.builder().key(kp.getPublic()).build()
                                                .thumbprint(Jwks.HASH.SHA256).toString()
                                                .replaceAll("=", "");
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
                                if (!accesible) {
                                        throw new IOException(
                                                        "Could not accessible acme-challenge folder, please properly configure the json.");
                                }
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
                                                                                        JSONStringof(ACMEJWS
                                                                                                        .withAccountLocation(
                                                                                                                        accountLocation,
                                                                                                                        nextNonce,
                                                                                                                        auth,
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
                }
                AtomicLong waitTimeSec = new AtomicLong(0);
                System.out.println("finalizing: ");
                waitTimeSec.set(0);
                while (waitTimeSec.get() != -1) {
                        Thread.sleep(Duration.ofSeconds(waitTimeSec.get()));
                        var finalizeRes = finalizeRequest(orderRes.getFinalize(), sslKeyPair);
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
                NewOrderResponse finalOrder = null;
                while (waitTimeSec.get() != -1) {
                        Thread.sleep(Duration.ofSeconds(waitTimeSec.get()));
                        var orderRes2 = getOrder(orderLocation);
                        finalOrder = orderRes2.thenApply((r) -> {
                                JSONObject orderJson = new JSONObject(r.body());
                                var status = orderJson.optString("status", "");
                                if (!status.equals(ResponseConstants.VALID)) {
                                        System.out.print("Waiting for the order to be valid... \n");
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
                                return orderJson;
                        }).get()
                                        .fromJson(NewOrderResponse.class);
                }
                String certUrl = finalOrder.getCertificate();
                return client.sendAsync(JoseHttpRequest.newBuilder(URI.create(certUrl))
                                .header("Accept", "application/pem-certificate-chain")
                                .POST(BodyPublishers.ofString(JSONStringof(
                                                ACMEJWS.withAccountLocation(accountLocation, nextNonce, certUrl,
                                                                kp.getPrivate()))))
                                .build(),
                                BodyHandlers.ofString())
                                .thenApply(this::processNonce)
                                .thenApply((r) -> r.body())
                                .get();
        }

        public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException,
                        ExecutionException, OperatorCreationException, CertificateException,
                        KeyStoreException {
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
                } catch (JSONException je) {
                        System.out.println("failed to load configuration json, default will be used instead");
                        je.printStackTrace();
                }

                Files.writeString(configJson, new JSONObject(config).toString(4), StandardCharsets.UTF_8);
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
                System.out.println("Getting Cert: ");
                var generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair sslKeyPair = generator.genKeyPair();
                String cert = validator.getCert(sslKeyPair);
                System.out.println(cert);
                List<X509Certificate> certs = new ArrayList<>();

                try (PEMParser reader = new PEMParser(new StringReader(cert))) {
                        JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                                        .setProvider(new BouncyCastleProvider());
                        Object nextPem;
                        while ((nextPem = reader.readObject()) != null) {
                                certs.add(converter.getCertificate((X509CertificateHolder) nextPem));
                        }
                }

                KeyStore store = KeyStore.getInstance("pkcs12");
                store.load(null, new char[] {});
                store.setKeyEntry("cert", sslKeyPair.getPrivate(),
                                "password".toCharArray(), certs.toArray(X509Certificate[]::new));
                try (var outputSteam = new FileOutputStream("key.p12")) {
                        store.store(outputSteam, "password".toCharArray());
                }
        }

}
