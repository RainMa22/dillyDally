package me.rainma22.dillydally.sslcert.states;


public interface CertificateGetterState {
        boolean isFinal();
        CertificateGetterState nextState();
}