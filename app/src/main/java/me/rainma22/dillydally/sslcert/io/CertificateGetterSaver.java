package me.rainma22.dillydally.sslcert.io;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetter;

public class CertificateGetterSaver {
    private ConfBean conf;

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateGetterSaver(ConfBean conf) {
        this.conf = conf;
    }

    public void SaveToFile( CertificateGetter cg) throws IOException {
        var acmeKeyPair = cg.getKeyPair();
        var sslConf = conf.getSslCertificateConf();
        Path acmeKeyPath = Path.of(sslConf.getPathToACMEPEM());
        LOGGER.info("Saving to Certificate getter to file {}", acmeKeyPath);
        Files.createDirectories(acmeKeyPath.getParent());
        try (var sslKeyOut = new JcaPEMWriter(new FileWriter(acmeKeyPath.toFile()))) {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                    .build(sslConf.getAcmePassword().toCharArray());
            sslKeyOut.writeObject(acmeKeyPair, encryptor);
        }
        var keyCertPair = cg.getCert();
        new SSLSaver(conf).SaveToFile(keyCertPair.getLeft(), keyCertPair.getRight());
        LOGGER.info("Saved to Certificate getter to file {}", acmeKeyPath);
    }

}
