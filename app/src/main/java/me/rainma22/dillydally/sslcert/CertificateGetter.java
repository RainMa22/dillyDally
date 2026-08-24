package me.rainma22.dillydally.sslcert;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
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
import java.security.PKCS12Attribute;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalTime;
import java.util.Date;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.random.RandomGenerator;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.bouncycastle.jcajce.BCFKSLoadStoreParameter.SignatureAlgorithm;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.X931SignatureSpi.SHA512WithRSAEncryption;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.PEMUtil;
import org.bouncycastle.openssl.PEMDecryptor;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
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
                // try (PEMParser parser = new PEMParser(new FileReader("acme.pem"))) {

                // var decryptorProvider = new JcePEMDecryptorProviderBuilder()
                // .build(httpConf.getAcmePassword().toCharArray());
                // JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                // .setProvider(new BouncyCastleProvider());
                // var pemKp = (PEMEncryptedKeyPair) parser.readObject();
                // PEMKeyPair pKp = pemKp.decryptKeyPair(decryptorProvider);
                // KeyPair kp = converter.getKeyPair(pKp);
                // }

                if (certGetter.currState instanceof CompletedState) {
                        CompletedState state = (CompletedState) certGetter.currState;
                        KeyPair sslKeyPair = state.getSslKeyPair();
                        var certs = state.getCertChain();
                        KeyStore store = KeyStore.getInstance("pkcs12");
                        store.load(null, new char[] {});
                        store.setKeyEntry("ssl", sslKeyPair.getPrivate(),
                                        sslConf.getSslKeyPassword().toCharArray(), certs);
                        Path sslPath = Path.of(sslConf.getPathToSSLP12());
                        Files.createDirectories(sslPath.getParent());
                        try (var outputSteam = new FileOutputStream(sslPath.toFile())) {
                                store.store(outputSteam,
                                                config.getSslCertificateConf().getKeyStorePassword().toCharArray());
                        }
                } else {
                        throw new IOException(((FailedState) certGetter.currState).getError());
                }
        }

}
