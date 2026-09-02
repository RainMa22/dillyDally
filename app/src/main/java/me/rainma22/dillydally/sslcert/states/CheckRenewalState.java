package me.rainma22.dillydally.sslcert.states;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.Base64.Encoder;

import org.json.JSONException;
import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.RenewalInfoResponse;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.SuggestedWindowBean;
import me.rainma22.dillydally.sslcert.ACMEHttpClient;

public class CheckRenewalState implements CertificateGetterState {

    private final long THRESHOLD_MILLISEC;
    private KeyPair kp;
    private String accountLocation;
    private KeyPair sslKeyPair;
    private X509Certificate[] certChain;
    private ConfBean conf;

    public CheckRenewalState(KeyPair kp, String accountLocation, KeyPair sslKeyPair, X509Certificate[] certChain,
            ConfBean conf) {
        this.kp = kp;
        this.accountLocation = accountLocation;
        this.sslKeyPair = sslKeyPair;
        this.certChain = certChain;
        this.conf = conf;
        THRESHOLD_MILLISEC = Duration.ofDays(conf.getSslCertificateConf().getRenewalThresholdInDays()).toMillis();
    }

    @Override
    public boolean isFinal() {
        return false;
    }

    /*
     * - ATTMEPTS to use ARI(RFC 9773) to check whether certificate needs renewing;
     * - IF ARI is supported:
     * -- CHECK using ARI
     * -- IF no renew needed, return CompletedState
     * -- ELSE return next ARI RENEWAL State
     * - ELSE
     * -- CHECK using CERTIFICATE's NOTAFTER timestamp
     * -- IF current time is some threshold before NOT-AFTER timestamp or current
     * time is after NOT-AFTER timestamp, request a new cert by returning
     * AccountCreatedState
     * -- ELSE return CompletedState as no renew needed.
     */
    @Override
    public CertificateGetterState nextState() {

        URI resourceLocationURI = URI.create(conf.getServerUrl());
        ResourceLocationResponse resourceLocations;
        try (var inStream = resourceLocationURI.toURL().openStream()) {
            resourceLocations = JSONObject.fromJson(new String(inStream.readAllBytes()),
                    ResourceLocationResponse.class);
            ACMEHttpClient client = new ACMEHttpClient(resourceLocations);
            if (resourceLocations.isARISupported()) {
                final Encoder base64url = Base64.getUrlEncoder().withoutPadding();
                byte[] serial = certChain[0].getSerialNumber().toByteArray();
                String akiBase64 = base64url.encodeToString(certChain[0].getExtensionValue("2.5.29.35"));
                String serialBase64 = base64url.encodeToString(serial);
                String certId = akiBase64 + "." + serialBase64;
                HttpRequest req = HttpRequest
                        .newBuilder(URI.create(resourceLocations.getRenewalInfo() + "/").resolve("/" + certId))
                        .GET()
                        .build();
                HttpResponse<String> res = client.send(req, BodyHandlers.ofString());
                RenewalInfoResponse renewalInfo = new RenewalInfoResponse();
                try {
                    renewalInfo = JSONObject.fromJson(res.body(), RenewalInfoResponse.class);
                } catch (JSONException je) {
                    // fallback, test the old-fashioned way.
                }
                SuggestedWindowBean suggestedWindow = renewalInfo.getSuggestedWindow();
                LocalDateTime notBefore = LocalDateTime
                        .from(DateTimeFormatter.ISO_DATE_TIME.parse(suggestedWindow.getNotBefore()));
                LocalDateTime notAfter = LocalDateTime
                        .from(DateTimeFormatter.ISO_DATE_TIME.parse(suggestedWindow.getNotAfter()));
                if (notBefore.isBefore(LocalDateTime.now()) && notAfter.isAfter(LocalDateTime.now())) {
                    // return a ARI-supporting renewal state
                    return new ARIAccountCreatedState(kp, resourceLocations, client, accountLocation, certId, conf);
                } else if (notAfter.isBefore(LocalDateTime.now())) {
                    // renew the old-fashioned way
                    return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
                } else {
                    // no renew needed
                    return new CompletedState(kp, accountLocation, sslKeyPair, certChain, conf);
                }
            } else {
                Date notAfter = certChain[0].getNotAfter();
                Date now = Date.from(Instant.now());
                if (notAfter.getTime() - now.getTime() < THRESHOLD_MILLISEC) {
                    // needs renewal
                    return new AccountCreatedState(kp, resourceLocations, client, accountLocation, conf);
                } else {
                    return new CompletedState(kp, accountLocation, sslKeyPair, certChain, conf);
                }
            }
        } catch (IOException | InterruptedException e) {
            return new FailedState(e);
        }

    }

    @Override
    public String getAccountLocation() {
        return accountLocation;
    }
}
