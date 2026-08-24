package me.rainma22.dillydally.sslcert;

import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.states.CompletedState;
import me.rainma22.dillydally.sslcert.states.FailedState;
import me.rainma22.dillydally.sslcert.states.InitializedState;
import me.rainma22.dillydally.sslcert.states.CertificateGetterState;

/**
 *
 */
public class CertificateGetter {
        private CertificateGetterState currState;
        private KeyPair kp;

        public CertificateGetter(ConfBean conf, KeyPair kp) throws IOException, InterruptedException {
                HttpClient client = HttpClient.newHttpClient();
                var resourceLocations = new JSONObject(
                                client.send(HttpRequest.newBuilder(URI.create(conf.getServerUrl()))
                                                .GET()
                                                .build(),
                                                HttpResponse.BodyHandlers.ofString())
                                                .body())
                                .fromJson(ResourceLocationResponse.class);
                this.kp = kp;
                currState = new InitializedState(kp, resourceLocations, conf);
        }

        private void nextState() {
                this.currState = currState.nextState();
        }

        public CertificateGetterState getCurrState() {
                return currState;
        }

        public KeyPair getKeyPair() {
                return kp;
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

                var sslConf = config.getSslCertificateConf();
                Files.writeString(configJson, new JSONObject(config).toString(4), StandardCharsets.UTF_8);

                CertificateGetter certGetter = new CertificateGetter(config, GenUtils.generateKeyPair());

                while (!certGetter.getCurrState().isFinal()) {
                        certGetter.nextState();
                        System.out.println(certGetter.currState.getClass().getName());
                }

                KeyPair acmeKeyPair = certGetter.getKeyPair();
                Path pemPath = Path.of(sslConf.getPathToACMEPEM());
                Files.createDirectories(pemPath.getParent());

                try (JcaPEMWriter writer = new JcaPEMWriter(
                                new FileWriter(Path.of(sslConf.getPathToACMEPEM()).toFile()))) {
                        PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                                        .build(sslConf.getAcmePassword().toCharArray());
                        writer.writeObject(acmeKeyPair, encryptor);
                }

                if (certGetter.currState instanceof CompletedState) {
                        CompletedState state = (CompletedState) certGetter.currState;
                        KeyPair sslKeyPair = state.getSslKeyPair();
                        var certs = state.getCertChain();
                        Path sslKeyPath = Path.of(sslConf.getPathToSSLKeyPEM());
                        Files.createDirectories(sslKeyPath.getParent());
                        try (var sslKeyOut = new JcaPEMWriter(new FileWriter(sslKeyPath.toFile()))) {
                                PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                                                .build(sslConf.getSslKeyPassword().toCharArray());
                                sslKeyOut.writeObject(sslKeyPair.getPrivate(), encryptor);
                        }
                        Path sslCertPath = Path.of(sslConf.getPathToSSLCertPEM());
                        Files.createDirectories(sslCertPath.getParent());
                        try (var sslCertOut = new JcaPEMWriter(new FileWriter(sslCertPath.toFile()))) {
                                for (var cert : certs) {
                                        sslCertOut.writeObject(cert);
                                }
                        }
                } else {
                        throw new IOException(((FailedState) certGetter.currState).getError());
                }
        }

}
