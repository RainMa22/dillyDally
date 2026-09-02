package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

import org.json.JSONObject;

import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.NewOrderResponse;
import me.rainma22.dillydally.sslcert.OrderIdentifier;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public class AccountCreatedState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        try {
            // create order
            var jws = ACMEJWS.withAccountLocation(ctx.getAccountLocation(), ctx.getClient().nextNonce(),
                    ctx.getResourceLocations().getNewOrder(),
                    ctx.getAcmeKeyPair().getPrivate());
            var identifiers = ctx.getConf().getDomains()
                    .stream()
                    .map(str -> {
                        var res = new OrderIdentifier();
                        res.setType("dns");
                        res.setValue(str);
                        return res;
                    }).toList();
            var payload = new JSONObject(
                    Map.of("identifiers", identifiers));
            jws.content(payload.toString());
            var reqBody = ACMEJWS.toString(jws);
            var req = JoseHttpRequest.newBuilder(URI.create(ctx.getResourceLocations().getNewOrder()))
                    .POST(BodyPublishers.ofString(reqBody))
                    .build();

            var res = ctx.getClient().send(req,
                    BodyHandlers.ofString());
            var orderLocation = res.headers().firstValue("Location").get();
            var newOrderResponse = JSONObject.fromJson(res.body(), NewOrderResponse.class);
            ctx.setOrderLocation(orderLocation);
            ctx.setOrderResponse(newOrderResponse);
            ctx.setOrderExpiry(LocalDateTime
                    .from(DateTimeFormatter.ISO_DATE_TIME.parse(newOrderResponse.getExpires())));

        } catch (Exception e) {
            ctx.updateError(e);
        }
    }

}
