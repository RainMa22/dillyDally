package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.OrderIdentifier;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;
import me.rainma22.dillydally.sslcert.ACMEHttpClient;

public class ARIAccountCreatedState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        try {
            KeyPair kp = ctx.getAcmeKeyPair();
            ResourceLocationResponse resourceLocations = ctx.getResourceLocations();
            ACMEHttpClient client = ctx.getClient();
            String accountLocation = ctx.getAccountLocation();
            String replaces = ctx.getReplaces();
            ConfBean conf = ctx.getConf();
            // create order
            var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), resourceLocations.getNewOrder(),
                    kp.getPrivate());
            var identifiers = conf.getDomains()
                    .stream()
                    .map(str -> {
                        var res = new OrderIdentifier();
                        res.setType("dns");
                        res.setValue(str);
                        return res;
                    }).toList();
            var payload = new JSONObject(
                    Map.of("identifiers", identifiers,
                            "replaces", replaces));
            jws.content(payload.toString());
            var reqBody = ACMEJWS.toString(jws);
            var req = JoseHttpRequest.newBuilder(URI.create(resourceLocations.getNewOrder()))
                    .POST(BodyPublishers.ofString(reqBody))
                    .build();

            var res = client.send(req,
                    BodyHandlers.ofString());
                        var orderLocation = res.headers().firstValue("Location").get();
                        var newOrderResponse = JSONObject.fromJson(res.body(), NewOrderResponse.class);
                        ctx.setOrderLocation(orderLocation);
                        ctx.setOrderResponse(newOrderResponse);
                        ctx.setOrderExpiry(LocalDateTime.from(
                            DateTimeFormatter.ISO_DATE_TIME.parse(newOrderResponse.getExpires())
                        ));
        } catch (Exception e) {
            // fallback to normal AccountCreatedState before fully failling
            // TODO: log the exception
            ctx.updateError(e);
        }
    }
}
