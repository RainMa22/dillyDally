package me.rainma22.dillydally.validation;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 *
 */
public class genUtils {

    public static PKCS10CertificationRequest genCSR() throws OperatorCreationException, NoSuchAlgorithmException {
        KeyPair keyPair = generateKeyPair();
// Create a PKCS10 Certification Request Builder
        PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Rainma22, C=CA"), keyPair.getPublic());
// Create a Content Signer for signing the CSR
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner contentSigner = signerBuilder.build(keyPair.getPrivate());
// Build the CSR
        PKCS10CertificationRequest csr = csrBuilder.build(contentSigner);
        return csr;
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        var gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.genKeyPair();
    }

}
