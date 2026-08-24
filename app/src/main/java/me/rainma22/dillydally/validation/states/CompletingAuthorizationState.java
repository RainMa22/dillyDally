package me.rainma22.dillydally.validation.states;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.validation.ACMEJWS;
import me.rainma22.dillydally.validation.AuthChallengeResponse;
import me.rainma22.dillydally.validation.JoseHttpRequest;
import me.rainma22.dillydally.validation.NewOrderResponse;
import me.rainma22.dillydally.validation.OrderChallenge;
import me.rainma22.dillydally.validation.ResourceLocationResponse;
import me.rainma22.dillydally.validation.ResponseConstants;
import me.rainma22.dillydally.validation.ValidationHttpClient;
import me.rainma22.dillydally.validation.challengecompletion.ChallengeCompletor;

public class CompletingAuthorizationState implements ValidatorState {

    private KeyPair kp;
    private ResourceLocationResponse resourceLocations;
    private ValidationHttpClient client;
    private String accountLocation;
    private String orderLocation;
    private LocalDateTime orderExpiry;
    private NewOrderResponse orderResponse;
    private Deque<String> authorizationToDo;
    private List<String> completed;
    private ConfBean conf;

    public CompletingAuthorizationState(KeyPair kp, ResourceLocationResponse resourceLocations,
            ValidationHttpClient client, String accountLocation, String orderLocation, LocalDateTime orderExpiry,
            NewOrderResponse orderResponse, Deque<String> authorizationToDo, List<String> completed, ConfBean conf) {
        this.kp = kp;
        this.resourceLocations = resourceLocations;
        this.client = client;
        this.accountLocation = accountLocation;
        this.orderLocation = orderLocation;
        this.orderExpiry = orderExpiry;
        this.orderResponse = orderResponse;
        this.authorizationToDo = authorizationToDo;
        this.completed = completed;
        this.conf = conf;
    }

    private AuthChallengeResponse getAuthChallenge(String authString)
            throws InterruptedException, ExecutionException, IOException {
        var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), authString, kp.getPrivate());
        var req = JoseHttpRequest.newBuilder(URI.create(authString))
                .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                .build();
        var res = client.send(req, BodyHandlers.ofString());
        return JSONObject.fromJson(res.body(), AuthChallengeResponse.class);
    }

    public CompletableFuture<Void> submitChallenge(String challengeUrl)
            throws IOException, InterruptedException {
        URI challengeUri = URI.create(challengeUrl);
        var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), challengeUrl,
                kp.getPrivate());
        jws.content("{}");
        var req = JoseHttpRequest.newBuilder(challengeUri)
                .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                .build();

        return CompletableFuture.runAsync(() -> {
            String status = "";
            int nRetries = conf.getHttpChallengeConf().getnPollingRetries();
            long retry = 0;
            do {
                try {
                    Thread.sleep(Duration.ofSeconds(retry));
                } catch (InterruptedException e) {
                    // ignored
                }
                HttpResponse<String> res;
                try {
                    res = client.send(req, BodyHandlers.ofString());
                    JSONObject obj = new JSONObject(res.toString());
                    status = obj.getString("status");
                    retry = res.headers().firstValueAsLong("Retry-After").orElse(1);
                } catch (IOException | InterruptedException | JSONException e) {
                    throw new RuntimeException(e);
                } catch (NumberFormatException nfe) {
                    retry = 1;
                }
            } while ((ResponseConstants.PENDING.equals(status) || ResponseConstants.PROCESSING.equals(status))
                    && (nRetries-- >= 0));
            if (!ResponseConstants.VALID.equals(status)) {
                throw new RuntimeException(
                        "Unexpected Status when completing challenge" + challengeUrl + ": " + status);
            }
            ;
        });
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    @Override
    public ValidatorState nextState() {
        if (orderExpiry.isBefore(LocalDateTime.now())) {
            // if expired: retry by regressing back to new Order
            return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
        }
        try {
            if (authorizationToDo.isEmpty()) {
                var ex = CompletableFuture.allOf(
                        completed.parallelStream()
                                .map(urlstr -> {
                                    try {
                                        return submitChallenge(urlstr);
                                    } catch (IOException | InterruptedException e) {
                                        return new RuntimeException(e);
                                    }
                                })
                                .toArray(CompletableFuture<?>[]::new))
                        .handle((x, e) -> e)
                        .get();
                if (ex == null) {
                    return new OrderValidationState(kp, resourceLocations, client, accountLocation, orderLocation,
                            orderExpiry, orderResponse, conf);
                } else
                    throw new IOException("Unexpected Exception: ", ex);
            }
            String authorizationLocation = authorizationToDo.pollFirst();
            AuthChallengeResponse challengeResponse = getAuthChallenge(authorizationLocation);
            OrderChallenge http01Challenge = challengeResponse.getChallenges().stream()
                    .filter(chal -> chal.getType().equalsIgnoreCase("http-01"))
                    .findAny()
                    .orElseThrow(() -> new UnsupportedOperationException("only http-01 challenges supported for now"));
            if (ResponseConstants.PENDING.equals(http01Challenge.getStatus())) {
                ChallengeCompletor completor = new ChallengeCompletor(conf.getHttpChallengeConf());
                completor.completeChallenge(http01Challenge, kp);
                if (!completor.isUriAccessible(URI.create(http01Challenge.getUrl()))) {
                    throw new IOException(
                            "Could not accessible acme-challenge uri, please properly configure the configuration json.");
                }
            }
            submitChallenge(http01Challenge.getUrl());
            return this; // = return new CompletingAuthorizationState(...) with authorizationToDo polled,
                         // and plus-1 completed
        } catch (Exception e) {
            return new FailedState(e);
        }
    }

}
