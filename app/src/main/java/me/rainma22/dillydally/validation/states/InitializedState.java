package me.rainma22.dillydally.validation.states;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.util.Map;

import org.json.JSONObject;

import io.jsonwebtoken.security.Jwks;
import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.validation.ACMEJWS;
import me.rainma22.dillydally.validation.JoseHttpRequest;
import me.rainma22.dillydally.validation.ResourceLocationResponse;
import me.rainma22.dillydally.validation.Utils;
import me.rainma22.dillydally.validation.ValidationHttpClient;

public class InitializedState implements ValidatorState {
    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ValidationHttpClient client;
    private ConfBean conf;

    public InitializedState(KeyPair kp, ResourceLocationResponse resourceLocation, ConfBean conf) {
        this.kp = kp;
        setResourceLocations(resourceLocation);
        this.conf = conf;
    }

    @Override
    public ValidatorState nextState() {
        try {
            // send new account request
            if (resourceLocations.getMeta().isExternalAccountRequired()) {
                throw new UnsupportedOperationException("External Account not supported");
            }
            var jwk = Jwks.builder().key(kp.getPublic()).build();
            var jws = ACMEJWS.withJWK(jwk, client.nextNonce(), resourceLocations.getNewAccount(), kp.getPrivate());
            jws.content(new JSONObject(
                    Map.of("termsOfServiceAgreed", true)).toString());
            var reqBody = Utils.JSONStringof(jws);
            var req = JoseHttpRequest.newBuilder(URI.create(resourceLocations.getNewAccount()))
                    .POST(HttpRequest.BodyPublishers.ofString(reqBody))
                    .build();
            return client.sendAsync(req, BodyHandlers.ofString())
                    .thenApply(res -> {
                        var accountLocation = res.headers().firstValue("Location").get();
                        return new AccountCreatedState(kp, resourceLocations, client,
                                accountLocation, conf);
                    }).get();
        } catch (Exception e) {
            return new FailedState(e);
        }
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    public ResourceLocationResponse getResourceLocations() {
        return resourceLocations;
    }

    public void setResourceLocations(ResourceLocationResponse resourceLocation) {
        this.resourceLocations = resourceLocation;
        client = new ValidationHttpClient(resourceLocation);
    }

}
