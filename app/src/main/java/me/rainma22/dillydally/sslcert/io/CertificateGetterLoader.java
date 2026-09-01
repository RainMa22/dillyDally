package me.rainma22.dillydally.sslcert.io;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.CertificateGetter;

public class CertificateGetterLoader {
    private ConfBean conf;

    public CertificateGetterLoader(ConfBean conf) {
        this.conf = conf;
    }

    public CertificateGetter loadCertGetter()
            throws NoSuchAlgorithmException, IOException, InterruptedException {
        var sslConf = conf.getSslCertificateConf();

        var acmeKeyPath = Path.of(sslConf.getPathToACMEPEM());
        try (PEMParser parser = new PEMParser(new FileReader(acmeKeyPath.toFile()))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            var decryptorProvider = new JcePEMDecryptorProviderBuilder()
                    .setProvider(new BouncyCastleProvider())
                    .build(sslConf.getAcmePassword()
                            .toCharArray());
            PEMEncryptedKeyPair pekp = (PEMEncryptedKeyPair) parser.readObject();
            var pkp = pekp.decryptKeyPair(decryptorProvider);
            KeyPair kp = converter.getKeyPair(pkp);
            return new CertificateGetter(conf, kp);
        } catch (IOException | InterruptedException e) {
            return new CertificateGetter(conf);
        }

    }

}
