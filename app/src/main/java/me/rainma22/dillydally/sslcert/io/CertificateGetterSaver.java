package me.rainma22.dillydally.sslcert.io;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import me.rainma22.dillydally.conf.ConfBean;

public class CertificateGetterSaver {
    private ConfBean conf;

    public CertificateGetterSaver(ConfBean conf) {
        this.conf = conf;
    }

    public void SaveToFile(KeyPair acmeKeyPair) throws IOException {
        var sslConf = conf.getSslCertificateConf();
        Path acmeKeyPath = Path.of(sslConf.getPathToACMEPEM());
        Files.createDirectories(acmeKeyPath.getParent());
        try (var sslKeyOut = new JcaPEMWriter(new FileWriter(acmeKeyPath.toFile()))) {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                    .build(sslConf.getAcmePassword().toCharArray());
            sslKeyOut.writeObject(acmeKeyPair, encryptor);
        }
    }

}
