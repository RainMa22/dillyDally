package me.rainma22.dillydally.sslcert.certificategetter;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.concurrent.ExecutionException;

import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.GenUtils;
import me.rainma22.dillydally.sslcert.io.SSLSaver;

/**
 *
 */
public class CertificateGetter {
        private CertificateGetterContext context;
        private ConfBean conf;

        public CertificateGetter(ConfBean conf) throws IOException, InterruptedException, NoSuchAlgorithmException {
                this(conf, GenUtils.generateKeyPair());
        }

        public CertificateGetter(ConfBean conf, KeyPair kp) throws IOException, InterruptedException {
                this.conf = conf;
                context = new CertificateGetterContext(kp, conf);
        }

        public Pair<KeyPair, X509Certificate[]> getCert() {
                do {
                        // check for updates if already completed
                        nextState();
                        // System.out.println(currState.getClass().getName());
                } while (context.getCertChain() == null
                                && context.getNumRetries() < conf.getSslCertificateConf().getnPollingRetries());

                return Pair.of(context.getSslKeyPair(), context.getCertChain());
        }

        public void setCert(KeyPair sslKeyPair, X509Certificate[] certs) {
                context.setCertChain(certs);
                context.setSslKeyPair(sslKeyPair);
                context.setOrderExpiry(LocalDateTime.MAX);
        }

        private void nextState() {
                context.getState().handle(context);
        }

        public KeyPair getKeyPair() {
                return context.getAcmeKeyPair();
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

                CertificateGetter certGetter = new CertificateGetter(config);
                certGetter.getCert();

                KeyPair acmeKeyPair = certGetter.getKeyPair();
                Path pemPath = Path.of(sslConf.getPathToACMEPEM());
                Files.createDirectories(pemPath.getParent());

                try (JcaPEMWriter writer = new JcaPEMWriter(
                                new FileWriter(Path.of(sslConf.getPathToACMEPEM()).toFile()))) {
                        PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                                        .build(sslConf.getAcmePassword().toCharArray());
                        writer.writeObject(acmeKeyPair, encryptor);
                }

                if (certGetter.context.getCertChain() != null) {
                        var certPair = certGetter.getCert();
                        KeyPair sslKeyPair = certPair.getLeft();
                        var certs = certPair.getRight();
                        new SSLSaver(config).SaveToFile(sslKeyPair, certs);
                } else {
                        throw new IOException(certGetter.context.getError());
                }
        }

}
