package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.Base64.Encoder;

import org.json.JSONObject;

import me.rainma22.dillydally.conf.ConfBean;
import me.rainma22.dillydally.sslcert.RenewalInfoResponse;
import me.rainma22.dillydally.sslcert.ResourceLocationResponse;
import me.rainma22.dillydally.sslcert.SuggestedWindowBean;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public class CheckRenewalState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        final X509Certificate[] certChain = ctx.getCertChain();
        final ConfBean conf = ctx.getConf();
        final long THRESHOLD_MILLISEC = Duration.ofDays(conf.getSslCertificateConf().getRenewalThresholdInDays())
                .toMillis();
        final ResourceLocationResponse resourceLocations = ctx.getResourceLocations();
        final var client = ctx.getClient();

        if (resourceLocations.isARISupported()) {
            try {
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
                renewalInfo = JSONObject.fromJson(res.body(), RenewalInfoResponse.class);
                SuggestedWindowBean suggestedWindow = renewalInfo.getSuggestedWindow();
                LocalDateTime notBefore = LocalDateTime
                        .from(DateTimeFormatter.ISO_DATE_TIME.parse(suggestedWindow.getNotBefore()));
                LocalDateTime notAfter = LocalDateTime
                        .from(DateTimeFormatter.ISO_DATE_TIME.parse(suggestedWindow.getNotAfter()));
                if (notBefore.isBefore(LocalDateTime.now())) {
                    // return a ARI-supporting renewal state
                    ctx.setOrderExpiry(LocalDateTime.MIN);
                    ctx.setReplaces(certId);
                    return;
                } else if (notAfter.isBefore(LocalDateTime.now())) {
                    ctx.setOrderExpiry(LocalDateTime.MIN);
                }
                // else: no renew needed
                return;
            } catch (Exception e) {
                ctx.getResourceLocations().setRenewalInfo(null);
                ctx.updateError(e);
                return;
            }
        } else {
            try {
                Date notAfter = certChain[0].getNotAfter();
                Date now = Date.from(Instant.now());
                if (notAfter.getTime() - now.getTime() < THRESHOLD_MILLISEC) {
                    // needs renewal
                    ctx.setOrderExpiry(LocalDateTime.MIN);
                } else {
                    return;
                }
            } catch (Exception e) {
                ctx.updateError(e);
                return;
            }
        }

    }
}
