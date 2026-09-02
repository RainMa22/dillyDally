package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.util.concurrent.CompletableFuture;

import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public class AuthorizationValidationState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        try {
            CompletableFuture.allOf(
                    ctx.getCompletedChallenges().stream().toArray(CompletableFuture<?>[]::new))
                    .join();
            ctx.getCompletedChallenges().clear();
        } catch (Exception e) {
            ctx.updateError(e);
        }
    }

}
