package me.rainma22.dillydally.sslcert.io;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetter;

public class CertificateGetterLoader {
    private ConfBean conf;
    private static final Logger LOGGER = LogManager.getLogger();
    public CertificateGetterLoader(ConfBean conf) {
        this.conf = conf;
    }

    public CertificateGetter loadCertGetter()
            throws NoSuchAlgorithmException, IOException, InterruptedException {
        var sslConf = conf.getSslCertificateConf();

        var acmeKeyPath = Path.of(sslConf.getPathToACMEPEM());
        CertificateGetter cGetter;
        try (PEMParser parser = new PEMParser(new FileReader(acmeKeyPath.toFile()))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            var decryptorProvider = new JcePEMDecryptorProviderBuilder()
                    .setProvider(new BouncyCastleProvider())
                    .build(sslConf.getAcmePassword()
                            .toCharArray());
            PEMEncryptedKeyPair pekp = (PEMEncryptedKeyPair) parser.readObject();
            var pkp = pekp.decryptKeyPair(decryptorProvider);
            KeyPair kp = converter.getKeyPair(pkp);
            cGetter = new CertificateGetter(conf, kp);
        } catch (FileNotFoundException | InterruptedException e) {
            LOGGER.warn("Could not load saved PEM key and certificate, will try to regenerate.");
            LOGGER.warn(e);
            cGetter = new CertificateGetter(conf);
        }
        
        try {
            var sslLoader = new SSLLoader(conf);
            var certs = sslLoader.loadSSLCertificates();
            var kp = sslLoader.loadSSLKeyPair();
            // promote the state to completed if keys exists
            cGetter.setCert(kp, certs);
        } catch (CertificateException | IOException e) {
            //ignored
        }

        return cGetter;
    }

}
