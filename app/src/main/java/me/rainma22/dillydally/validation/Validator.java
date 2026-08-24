package me.rainma22.dillydally.validation;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.operator.OperatorCreationException;
import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.validation.states.CompletedState;
import me.rainma22.dillydally.validation.states.FailedState;
import me.rainma22.dillydally.validation.states.InitializedState;
import me.rainma22.dillydally.validation.states.ValidatorState;

/**
 *
 */
public class Validator {
        private ValidatorState currState;

        public Validator(ConfBean conf, KeyPair kp) throws IOException, InterruptedException {
                HttpClient client = HttpClient.newHttpClient();
                var resourceLocations = new JSONObject(
                                client.send(HttpRequest.newBuilder(URI.create(conf.getServerUrl()))
                                                .GET()
                                                .build(),
                                                HttpResponse.BodyHandlers.ofString())
                                                .body())
                                .fromJson(ResourceLocationResponse.class);
                currState = new InitializedState(kp, resourceLocations, conf);
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

                Validator validator = new Validator(config, GenUtils.generateKeyPair());

                while (!validator.currState.isFinal()) {
                        validator.currState = validator.currState.nextState();
                        System.out.println(validator.currState.getClass().getName());
                }
                if (validator.currState instanceof CompletedState) {
                        CompletedState state = (CompletedState) validator.currState;
                        KeyPair sslKeyPair = state.getSslKeyPair();
                        var certs = state.getCertChain();
                        KeyStore store = KeyStore.getInstance("pkcs12");
                        store.load(null, new char[] {});
                        store.setKeyEntry("cert", sslKeyPair.getPrivate(),
                                        "password".toCharArray(), certs);
                        try (var outputSteam = new FileOutputStream("key.p12")) {
                                store.store(outputSteam, "password".toCharArray());
                        }
                } else {
                        throw new IOException(((FailedState) validator.currState).getError());
                }
        }

}
