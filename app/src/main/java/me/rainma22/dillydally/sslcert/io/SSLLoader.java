package me.rainma22.dillydally.sslcert.io;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import me.rainma22.dillydally.conf.ConfBean;

public class SSLLoader {
    private ConfBean conf;
    private static final Logger LOGGER = LogManager.getLogger();

    public SSLLoader(ConfBean conf) {
        this.conf = conf;
    }

    public X509Certificate[] loadSSLCertificates() throws IOException, CertificateException {
        var sslConf = conf.getSslCertificateConf();
        LOGGER.info("Loading ssl certificate from {}", sslConf.getPathToSSLCertPEM());
        try (PEMParser parser = new PEMParser(new FileReader(sslConf.getPathToSSLCertPEM()))) {
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            Object obj;
            List<X509Certificate> certList = new ArrayList<>();
            while ((obj = parser.readObject()) != null) {
                certList.add(converter.getCertificate((X509CertificateHolder) obj));
            }
            LOGGER.info("Loaded {} ssl certificate{} from {}", certList.size(),
                    certList.size() == 1 ? "" : "s", 
                    sslConf.getPathToSSLCertPEM());
            return certList.stream().toArray(X509Certificate[]::new);
        }
    }

    public KeyPair loadSSLKeyPair() throws IOException {
        var sslConf = conf.getSslCertificateConf();
        KeyPair kp;
        LOGGER.info("Loading ssl keypair from {}", sslConf.getPathToSSLKeyPEM());
        try (PEMParser parser = new PEMParser(new FileReader(sslConf.getPathToSSLKeyPEM()))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            var decryptorProvider = new JcePEMDecryptorProviderBuilder()
                    .setProvider(new BouncyCastleProvider())
                    .build(sslConf.getSslKeyPassword().toCharArray());
            PEMEncryptedKeyPair pekp = (PEMEncryptedKeyPair) parser.readObject();
            var pkp = pekp.decryptKeyPair(decryptorProvider);
            kp = converter.getKeyPair(pkp);
        }
        LOGGER.info("Loaded ssl keypair from {}", sslConf.getPathToSSLKeyPEM());
        return kp;
    }

}
