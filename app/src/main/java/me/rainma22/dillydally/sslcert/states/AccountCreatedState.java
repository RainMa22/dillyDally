package me.rainma22.dillydally.sslcert.states;

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
import me.rainma22.dillydally.sslcert.ACMEHttpClient;

public class AccountCreatedState implements CertificateGetterState {
    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ACMEHttpClient client;
    private String accountLocation;
    private ConfBean conf;

    public AccountCreatedState(KeyPair kp, ResourceLocationResponse resourceLocations,
            ACMEHttpClient client, String accountLocation, ConfBean conf) {
        this.kp = kp;
        this.resourceLocations = resourceLocations;
        this.client = client;
        this.accountLocation = accountLocation;
        this.conf = conf;
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public CertificateGetterState nextState() {
        try {
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
                    Map.of("identifiers", identifiers));
            jws.content(payload.toString());
            var reqBody = ACMEJWS.toString(jws);
            var req = JoseHttpRequest.newBuilder(URI.create(resourceLocations.getNewOrder()))
                    .POST(BodyPublishers.ofString(reqBody))
                    .build();

            return client.sendAsync(req,
                    BodyHandlers.ofString())
                    .thenApply(res -> {
                        var orderLocation = res.headers().firstValue("Location").get();
                        var newOrderResponse = JSONObject.fromJson(res.body(), NewOrderResponse.class);
                        return new OrderCreatedState(kp, resourceLocations, client, accountLocation, orderLocation, 
                            LocalDateTime.from(DateTimeFormatter.
                                ISO_DATE_TIME.parse(newOrderResponse.getExpires())), 
                                newOrderResponse, conf);
                    }).get();
        } catch (Exception e) {
            return new FailedState(e);
        }
    }

}
