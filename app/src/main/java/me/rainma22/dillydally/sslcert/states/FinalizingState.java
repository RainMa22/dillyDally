package me.rainma22.dillydally.sslcert.states;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Map;

import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.GenUtils;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.ResponseConstants;
import me.rainma22.dillydally.sslcert.ValidationHttpClient;

/**
 * FinalizingState
 */
public class FinalizingState implements CertificateGetterState {
    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ValidationHttpClient client;
    private String accountLocation;
    private String orderLocation;
    private LocalDateTime orderExpiry;
    private NewOrderResponse orderResponse;
    private ConfBean conf;

    public FinalizingState(KeyPair kp, ResourceLocationResponse resourceLocations, ValidationHttpClient client,
            String accountLocation, String orderLocation, LocalDateTime orderExpiry, NewOrderResponse orderResponse,
            ConfBean conf) {
        this.kp = kp;
        this.resourceLocations = resourceLocations;
        this.client = client;
        this.accountLocation = accountLocation;
        this.orderLocation = orderLocation;
        this.orderResponse = orderResponse;
        this.orderExpiry = orderExpiry;
        this.conf = conf;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public CertificateGetterState nextState() {
        try {
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
            if (ResponseConstants.PROCESSING.equals(status)) {
                return new PollForCertificateState(kp, resourceLocations,
                        client, accountLocation, orderLocation, orderExpiry, sslKeyPair, conf);
            } else {
                throw new IOException("Unexpected status: " + status);
            }
        } catch (Exception e) {
            return new FailedState(e);
        }

    }

}
