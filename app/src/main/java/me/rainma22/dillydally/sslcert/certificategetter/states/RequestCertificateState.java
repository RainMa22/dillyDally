package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Map;

import org.json.JSONObject;

import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.GenUtils;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.ResponseConstants;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

/**
 * FinalizingState
 */
public class RequestCertificateState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        try {
            var conf = ctx.getConf();
            var orderResponse = ctx.getOrderResponse();
            var accountLocation = ctx.getAccountLocation();
            var client = ctx.getClient();
            var kp = ctx.getAcmeKeyPair();
            Encoder Base64Url = Base64.getUrlEncoder();
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair sslKeyPair = gen.genKeyPair();
            var csr = GenUtils.genCSR(conf, sslKeyPair);
            String finalizeUrl = orderResponse.getFinalize();
            URI finalizeUri = URI.create(finalizeUrl);

            var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), finalizeUrl, kp.getPrivate());
            jws.content(new JSONObject(
                    Map.of("CSR", Base64Url.encodeToString(csr.getEncoded())))
                    .toString());

            var req = JoseHttpRequest.newBuilder(finalizeUri)
                    .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                    .build();
            var res = client.sendAsync(req, BodyHandlers.ofString())
                    .thenApply(r -> new JSONObject(r.body()))
                    .get();
            String status = res.get("status").toString();
            if (ResponseConstants.PROCESSING.equals(status) || ResponseConstants.VALID.equals(status)) {
                ctx.setSslKeyPair(sslKeyPair);
            } else {
                throw new IOException("Unexpected status: " + status);
            }
        } catch (Exception e) {
            ctx.updateError(e);
        }

    }

}
