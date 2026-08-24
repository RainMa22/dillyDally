package me.rainma22.dillydally.sslcert;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import me.rainma22.dillydally.conf.ConfBean;

/**
 *
 */
public class GenUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PKCS10CertificationRequest genCSR(ConfBean conf, KeyPair kp)
            throws OperatorCreationException, NoSuchAlgorithmException, IOException {
        
        KeyPair keyPair = kp;

        // Create a PKCS10 Certification Request Builder
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal(String.format("CN=%s", conf.getDomains().get(0))), keyPair.getPublic());

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        if (conf.getDomains().size() > 1) {
            var subDomains = conf.getDomains().subList(1, conf.getDomains().size());
            extensionsGenerator.addExtension(Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(
                            subDomains.stream()
                                    .map(domain -> new GeneralName(GeneralName.dNSName, domain))
                                    .toArray(GeneralName[]::new)));

            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensionsGenerator.generate());
        }

        // Create a Content Signer for signing the CSR
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner contentSigner = signerBuilder.build(keyPair.getPrivate());

        // Build the CSR
        PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);

        return csr;
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        var gen = KeyPairGenerator.getInstance("ECDSA");
        gen.initialize(256);
        return gen.genKeyPair();
    }

}
