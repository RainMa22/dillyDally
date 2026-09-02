package me.rainma22.dillydally.sslcert.certificategetter.states;

import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public class FailedState implements CertificateGetterState {

    private Exception error;

    public FailedState(Exception error) {
        this.error = error;
    }

    @Override
    public void handle(CertificateGetterContext ctx) {
        ctx.updateError(error);
        return;
    }
}
