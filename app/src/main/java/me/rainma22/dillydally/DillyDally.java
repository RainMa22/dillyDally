package me.rainma22.dillydally;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.CertificateGetter;
import me.rainma22.dillydally.sslcert.io.CertificateGetterLoader;

public class DillyDally {
    private ConfBean conf;
    private CertificateGetterLoader certGetterLoader;

    public DillyDally(ConfBean conf) {
        this.conf = conf;
        certGetterLoader = new CertificateGetterLoader(conf);
    }

    private KeyStore initializeKeyStore()
            throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, new char[0]);
        IOException exception;
        try {
            CertificateGetter certGetter = certGetterLoader.loadCertGetter();
            var finalState = certGetter.getCert().get();
            var kp = finalState.getSslKeyPair();
            var certs = finalState.getCertChain();
            ks.setKeyEntry("entry", kp.getPrivate(), new char[0], certs);
            return ks;
        } catch (NoSuchAlgorithmException | IOException | InterruptedException | ExecutionException e) {
            exception = new IOException(e);
        }
        throw exception;
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
