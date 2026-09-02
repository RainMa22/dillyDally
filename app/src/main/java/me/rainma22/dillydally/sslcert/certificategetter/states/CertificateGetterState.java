package me.rainma22.dillydally.sslcert.certificategetter.states;

import me.rainma22.dillydally.sslcert.certificategetter.CertificateGetterContext;

public interface CertificateGetterState {
        void handle(CertificateGetterContext ctx);
}