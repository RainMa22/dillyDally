package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;

import org.json.JSONObject;

import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.ResponseConstants;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

/**
 * OrderValidationState
 */
public class OrderValidationState implements CertificateGetterState {

    private CompletableFuture<HttpResponse<String>> getOrder(CertificateGetterContext ctx, String orderUrl)
            throws IOException, InterruptedException {
        var accountLocation = ctx.getAccountLocation();
        var client = ctx.getClient();
        var kp = ctx.getAcmeKeyPair();
        URI orderUri = URI.create(orderUrl);
        var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), orderUrl, kp.getPrivate());
        var req = JoseHttpRequest.newBuilder(orderUri)
                .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                .build();
        return client.sendAsync(req, BodyHandlers.ofString());
    }

    @Override
    public void handle(CertificateGetterContext ctx) {
        var conf = ctx.getConf();
        // poll until order is validated
        int nRetries = conf.getSslCertificateConf().getnPollingRetries();
        String status = ResponseConstants.PENDING;
        NewOrderResponse orderValidationResponse = ctx.getOrderResponse();
        var orderLocation = ctx.getOrderLocation();
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
                var orderRes2 = getOrder(ctx, orderLocation).get();
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
                    // orderValidationResponse = obj.fromJson(NewOrderResponse.class);
                    ctx.setOrderResponse(orderValidationResponse);
                    ctx.setOrderValidated(true);
                }
            }
            throw new IOException("Out of retries while waiting to order to finish");
        } catch (Exception e) {
            ctx.updateError(e);
        }
    }
}
