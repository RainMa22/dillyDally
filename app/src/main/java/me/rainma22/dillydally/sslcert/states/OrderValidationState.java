package me.rainma22.dillydally.sslcert.states;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;

import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.ResponseConstants;
import me.rainma22.dillydally.sslcert.ACMEHttpClient;

/**
 * OrderValidationState
 */
public class OrderValidationState implements CertificateGetterState {
    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ACMEHttpClient client;
    private String accountLocation;
    private String orderLocation;
    private LocalDateTime orderExpiry;
    private NewOrderResponse orderResponse;
    private ConfBean conf;

    public OrderValidationState(KeyPair kp, ResourceLocationResponse resourceLocations, ACMEHttpClient client,
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

    public CompletableFuture<HttpResponse<String>> getOrder(String orderUrl)
            throws IOException, InterruptedException {
        URI orderUri = URI.create(orderUrl);
        var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), orderUrl, kp.getPrivate());
        var req = JoseHttpRequest.newBuilder(orderUri)
                .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                .build();
        return client.sendAsync(req, BodyHandlers.ofString());
    }

    @Override
    public CertificateGetterState nextState() {
        if (orderExpiry.isBefore(LocalDateTime.now())) {
            // if expired: retry by regressing back to new Order
            return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
        }
        // poll until order is validated
        int nRetries = conf.getSslCertificateConf().getnPollingRetries();
        String status = ResponseConstants.PENDING;
        NewOrderResponse orderValidationResponse = orderResponse;
        long waitTimeSec = 0;
        try {
            while ((ResponseConstants.PENDING.equals(status)
                    || ResponseConstants.PROCESSING.equals(status))
                    && nRetries-- > 0) {
                try {
                    Thread.sleep(Duration.ofSeconds(waitTimeSec));
                } catch (InterruptedException e) {
                    // ignored
                }
                var orderRes2 = getOrder(orderLocation).get();
                JSONObject obj = new JSONObject(orderRes2.body());
                status = obj.getString("status");
                if (ResponseConstants.INVALID.equals(status)) {
                    throw new IOException("Bad status: " + status);
                }
                try {
                    waitTimeSec = orderRes2.headers().firstValueAsLong("Retry-After").getAsLong();
                } catch (NoSuchElementException | NumberFormatException e) {
                    waitTimeSec = 1;
                }
                if (ResponseConstants.READY.equals(status)) {
                    orderValidationResponse = obj.fromJson(NewOrderResponse.class);
                    return new FinalizingState(kp, resourceLocations, client, accountLocation, orderLocation,
                            orderExpiry, orderValidationResponse, conf);
                }
            }
            throw new IOException("Out of retries while waiting to order to finish");
          } catch (Exception e) {
            return new FailedState(e);
        }
    }

}
