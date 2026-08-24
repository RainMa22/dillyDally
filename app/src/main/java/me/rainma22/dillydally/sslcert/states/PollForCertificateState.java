package me.rainma22.dillydally.sslcert.states;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.ResponseConstants;
import me.rainma22.dillydally.sslcert.ValidationHttpClient;

/**
 * PollForCertificateState
 */
public class PollForCertificateState implements CertificateGetterState {
    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ValidationHttpClient client;
    private String accountLocation;
    private String orderLocation;
    private LocalDateTime orderExpiry;
    private KeyPair sslKeyPair;
    private ConfBean conf;

    public PollForCertificateState(KeyPair kp, ResourceLocationResponse resourceLocations, ValidationHttpClient client,
            String accountLocation, String orderLocation, LocalDateTime orderExpiry, KeyPair sslKeyPair,
            ConfBean conf) {
        this.kp = kp;
        this.resourceLocations = resourceLocations;
        this.client = client;
        this.accountLocation = accountLocation;
        this.orderLocation = orderLocation;
        this.orderExpiry = orderExpiry;
        this.sslKeyPair = sslKeyPair;
        this.conf = conf;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public CertificateGetterState nextState() {
        if(orderExpiry.isBefore(LocalDateTime.now())){
            return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
        }
        int nRetries = conf.getHttpChallengeConf().getnPollingRetries();
        long retrySec = 0;
        while (nRetries-- > 0) {
            try {
                try {
                    Thread.sleep(Duration.ofSeconds(retrySec));
                } catch (InterruptedException e) {
                    // ignored
                }
                var res = getOrder(orderLocation).get();
                JSONObject obj = new JSONObject(res.body());
                if (!ResponseConstants.VALID.equals(obj.get("status").toString())) {
                    try {
                        retrySec = res.headers().firstValueAsLong("Retry-After").getAsLong();
                    } catch (NumberFormatException | NoSuchElementException e) {
                        retrySec = 1;
                    }
                    continue;
                }
                NewOrderResponse orderResponse = obj.fromJson(NewOrderResponse.class);
                String certUrl = orderResponse.getCertificate();

                // need to use POST-as-GET instead of just GET even if Let's encrypt allows it
                var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), certUrl, kp.getPrivate());
                var req = JoseHttpRequest.newBuilder(URI.create(orderResponse.getCertificate()))
                        .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                        .build();
                List<X509Certificate> certs = new ArrayList<>();
                try (PEMParser parser = new PEMParser(
                        new StringReader(client.send(req, BodyHandlers.ofString()).body()))) {
                    JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                            .setProvider(new BouncyCastleProvider());
                    Object nextPem;
                    while ((nextPem = parser.readObject()) != null) {
                        certs.add(converter.getCertificate((X509CertificateHolder) nextPem));
                    }
                }
                X509Certificate[] certChain = certs.stream().toArray(X509Certificate[]::new);
                return new CompletedState(kp, accountLocation, sslKeyPair, certChain, conf);
            } catch (Exception e) {
                // TODO: add logging for exceptions caught
            }
        }
        return new FailedState(new IOException("Out of retries when polling for certificate"));
    }

    public CompletableFuture<HttpResponse<String>> getOrder(String orderUrl)
            throws IOException, InterruptedException {
        URI orderUri = URI.create(orderUrl);
        var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), orderUrl, kp.getPrivate());
        var req = JoseHttpRequest.newBuilder(orderUri)
                .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                .build();
        return client.sendAsync(req, BodyHandlers.ofString());
    }
}
