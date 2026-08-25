package me.rainma22.dillydally;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import me.rainma22.dillydally.conf.ConfBean;

public class DillyDally {
    private ConfBean conf;
    public DillyDally(ConfBean conf){
        this.conf = conf;
    }
    private KeyPair loadKeyPairFromFile() throws FileNotFoundException, IOException {
        var sslConf = conf.getSslCertificateConf();
        KeyPair kp;
        try (PEMParser parser = new PEMParser(new FileReader(sslConf.getPathToSSLKeyPEM()))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            var decryptorProvider = new JcePEMDecryptorProviderBuilder()
                    .setProvider(new BouncyCastleProvider())
                    .build(sslConf.getSslKeyPassword().toCharArray());
            PEMEncryptedKeyPair pekp = (PEMEncryptedKeyPair) parser.readObject();
            var pkp = pekp.decryptKeyPair(decryptorProvider);
            kp = converter.getKeyPair(pkp);
        }
        return kp;
    }

    private X509Certificate[] loadCertificatesFromFile()
            throws CertificateException, FileNotFoundException, IOException {
        var sslConf = conf.getSslCertificateConf();
        try (PEMParser parser = new PEMParser(new FileReader(sslConf.getPathToSSLCertPEM()))) {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            Object obj;
            List<Certificate> certList = new ArrayList<>();
            while ((obj = parser.readObject()) != null) {
                certList.add(converter.getCertificate((X509CertificateHolder) obj));
            }
            return certList.stream().toArray(X509Certificate[]::new);
        }
    }

    private KeyStore initializeKeyStore()
            throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, new char[0]);
        KeyPair kp = loadKeyPairFromFile();
        X509Certificate[] certs = loadCertificatesFromFile();
        ks.setKeyEntry("entry", kp.getPrivate(), new char[0], certs);
        return ks;
    }

    public HttpServer createHttp() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(conf.getHttpPort()), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        return server;
    }

    public HttpsServer createHttps()
            throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException,
            UnrecoverableKeyException, KeyManagementException {

        var keyStore = initializeKeyStore();
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, new char[0]);

        // Set up the trust manager factory
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);

        HttpsServer server = HttpsServer.create(new InetSocketAddress(conf.getHttpsPort()), 0);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        server.setHttpsConfigurator(new HttpsConfigurator(ctx) {
            public void configure(HttpsParameters params) {
                try {
                    // Initialise the SSL context
                    SSLContext c = SSLContext.getDefault();
                    SSLEngine engine = c.createSSLEngine();
                    params.setNeedClientAuth(false);
                    params.setCipherSuites(engine.getEnabledCipherSuites());
                    params.setProtocols(engine.getEnabledProtocols());

                    // Get the default parameters
                    SSLParameters defaultSSLParameters = c.getDefaultSSLParameters();
                    params.setSSLParameters(defaultSSLParameters);
                } catch (Exception ex) {
                    // ILogger log = new LoggerFactory().getLogger();
                    // log.exception(ex);
                    // log.error("Failed to create HTTPS port");
                }
            }
        });
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        return server;
    }
}
