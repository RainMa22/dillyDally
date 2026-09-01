package me.rainma22.dillydally.sslcert.io;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;

import me.rainma22.dillydally.conf.ConfBean;

public class SSLSaver {

    private ConfBean conf;

    public SSLSaver(ConfBean conf) {
        this.conf = conf;

    }

    public void SaveToFile(KeyPair sslKeyPair, X509Certificate[] certs) throws IOException {
        var sslConf = conf.getSslCertificateConf();
        Path sslKeyPath = Path.of(sslConf.getPathToSSLKeyPEM());
        Files.createDirectories(sslKeyPath.getParent());
        try (var sslKeyOut = new JcaPEMWriter(new FileWriter(sslKeyPath.toFile()))) {
            PEMEncryptor encryptor = new JcePEMEncryptorBuilder("AES-256-CBC")
                    .build(sslConf.getSslKeyPassword().toCharArray());
            sslKeyOut.writeObject(sslKeyPair.getPrivate(), encryptor);
        }

        Path sslCertPath = Path.of(sslConf.getPathToSSLCertPEM());
        Files.createDirectories(sslCertPath.getParent());
        try (var sslCertOut = new JcaPEMWriter(new FileWriter(sslCertPath.toFile()))) {
            for (var cert : certs) {
                sslCertOut.writeObject(cert);
            }
        }
    }
}
