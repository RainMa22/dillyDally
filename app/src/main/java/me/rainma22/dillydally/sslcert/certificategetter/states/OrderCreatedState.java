package me.rainma22.dillydally.sslcert.certificategetter.states;

import java.util.ArrayDeque;
import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public class OrderCreatedState implements CertificateGetterState {

    @Override
    public void handle(CertificateGetterContext ctx) {
        try {
            var authorizations = ctx.getOrderResponse().getAuthorizations();
            ctx.setAuthorizationToDo(new ArrayDeque<>(authorizations));
        } catch (Exception e) {
            ctx.updateError(e);
        }
    }

}
