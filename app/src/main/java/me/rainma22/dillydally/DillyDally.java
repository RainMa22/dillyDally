package me.rainma22.dillydally;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executors;
import java.util.concurrent.ForkJoinPool;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetter;
import me.rainma22.dillydally.sslcert.io.CertificateGetterLoader;
import me.rainma22.dillydally.sslcert.io.CertificateGetterSaver;

public class DillyDally {
    private static final Logger LOGGER = LogManager.getLogger();
    private ConfBean conf;
    private CertificateGetterLoader certGetterLoader;

    public DillyDally(ConfBean conf) {
        this.conf = conf;
        certGetterLoader = new CertificateGetterLoader(conf);
    }

    private KeyStore initializeKeyStore()
            throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
                LOGGER.info("loading keyStore");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, new char[0]);
        IOException exception;
        try {
            CertificateGetter certGetter = certGetterLoader.loadCertGetter();
            var finalState = certGetter.getCert();
            var kp = finalState.getLeft();
            var certs = finalState.getRight();
            ks.setKeyEntry("entry", kp.getPrivate(), new char[0], certs);
            ForkJoinPool.commonPool().submit(() -> {
                try {
                    new CertificateGetterSaver(conf).SaveToFile(kp);
                } catch (IOException e) {
                    LOGGER.warn("failed to save gotten certificate");
                    LOGGER.warn(e);
                }
            });
            LOGGER.info("finished loading keyStore");
            return ks;
        } catch (NoSuchAlgorithmException | IOException | InterruptedException e) {
            exception = new IOException(e);
        }
        throw exception;
    }

    public HttpServer createHttp() throws IOException {
        LOGGER.info("Creating Http Server");
        HttpServer server = HttpServer.create(new InetSocketAddress(conf.getHttpPort()), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        LOGGER.info("Http Server Created");
        return server;
    }

    public HttpsServer createHttps()
            throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException,
            UnrecoverableKeyException, KeyManagementException {
        LOGGER.info("Creating Https Server");
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
                    LOGGER.error("Failed to create HTTPS port");
                    LOGGER.error(ex);
                }
            }
        });
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        LOGGER.info("Https Server Created");
        return server;
    }
}
