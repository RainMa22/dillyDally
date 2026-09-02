package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.sslcert.ACMEJWS;
import me.rainma22.dillydally.sslcert.AuthChallengeResponse;
import me.rainma22.dillydally.sslcert.JoseHttpRequest;
import me.rainma22.dillydally.sslcert.OrderChallenge;
import me.rainma22.dillydally.sslcert.ResponseConstants;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;
import me.rainma22.dillydally.sslcert.challengecompletion.ChallengeCompletor;

public class CompletingAuthorizationState implements CertificateGetterState {

    private AuthChallengeResponse getAuthChallenge(CertificateGetterContext ctx, String authString)
            throws InterruptedException, ExecutionException, IOException {
        var accountLocation = ctx.getAccountLocation();
        var client = ctx.getClient();
        var kp = ctx.getAcmeKeyPair();
        var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), authString, kp.getPrivate());
        var req = JoseHttpRequest.newBuilder(URI.create(authString))
                .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                .build();
        var res = client.send(req, BodyHandlers.ofString());
        return JSONObject.fromJson(res.body(), AuthChallengeResponse.class);
    }

    public CompletableFuture<Void> submitChallenge(CertificateGetterContext ctx, String challengeUrl)
            throws IOException, InterruptedException {
        var accountLocation = ctx.getAccountLocation();
        var client = ctx.getClient();
        var kp = ctx.getAcmeKeyPair();
        URI challengeUri = URI.create(challengeUrl);

        return CompletableFuture.runAsync(() -> {

            String status = "";
            int nRetries = ctx.getConf().getSslCertificateConf().getnPollingRetries();
            long retry = 0;
            do {
                try {
                    Thread.sleep(Duration.ofSeconds(retry));
                } catch (InterruptedException e) {
                    // ignored
                }
                HttpResponse<String> res;
                try {
                    var jws = ACMEJWS.withAccountLocation(accountLocation, client.nextNonce(), challengeUrl,
                            kp.getPrivate());
                    jws.content("{}");
                    var req = JoseHttpRequest.newBuilder(challengeUri)
                            .POST(BodyPublishers.ofString(ACMEJWS.toString(jws)))
                            .build();
                    res = client.send(req, BodyHandlers.ofString());
                    JSONObject obj = new JSONObject(res.body());
                    status = obj.get("status").toString();
                    retry = res.headers().firstValueAsLong("Retry-After").orElse(1);
                } catch (IOException | InterruptedException | JSONException e) {
                    throw new RuntimeException(e);
                } catch (NumberFormatException nfe) {
                    retry = 1;
                }
            } while ((ResponseConstants.PENDING.equals(status) || ResponseConstants.PROCESSING.equals(status)
                    || "409".equals(status))
                    && (nRetries-- >= 0));
            if (!ResponseConstants.VALID.equals(status)) {
                throw new RuntimeException(
                        "Unexpected Status when completing challenge" + challengeUrl + ": " + status);
            }
        });
    }

    @Override
    public void handle(CertificateGetterContext ctx) {
        var kp = ctx.getAcmeKeyPair();
        var conf = ctx.getConf();
        try {
            String authorizationLocation = ctx.getAuthorizationToDo().pollFirst();
            AuthChallengeResponse challengeResponse = getAuthChallenge(ctx, authorizationLocation);
            OrderChallenge http01Challenge = challengeResponse.getChallenges().stream()
                    .filter(chal -> chal.getType().equalsIgnoreCase("http-01"))
                    .findAny()
                    .orElseThrow(() -> new UnsupportedOperationException("only http-01 challenges supported for now"));
            if (ResponseConstants.PENDING.equals(http01Challenge.getStatus())) {
                ChallengeCompletor completor = new ChallengeCompletor(conf.getSslCertificateConf());
                completor.completeChallenge(http01Challenge, kp);
                if (!completor.isUriAccessible(URI.create(http01Challenge.getUrl()))) {
                    throw new IOException(
                            "Could not accessible acme-challenge uri, please properly configure the configuration json.");
                }
            }
            ctx.getCompletedChallenges().add(
                    submitChallenge(ctx, http01Challenge.getUrl()));
            return;
        } catch (Exception e) {
            ctx.updateError(e);
        }
    }
}
