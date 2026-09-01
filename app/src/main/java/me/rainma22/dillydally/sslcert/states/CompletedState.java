package me.rainma22.dillydally.sslcert.states;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.json.JSONPropertyIgnore;

import me.rainma22.dillydally.conf.ConfBean;

/**
 * CompletedState
 */
public class CompletedState implements CertificateGetterState {
    private KeyPair kp;
    private String accountLocation;
    private KeyPair sslKeyPair;
    private X509Certificate[] certChain;
    private ConfBean conf;

    public CompletedState(KeyPair kp, String accountLocation, KeyPair sslKeyPair, X509Certificate[] certChain,
            ConfBean conf) {
        this.kp = kp;
        this.accountLocation = accountLocation;
        this.sslKeyPair = sslKeyPair;
        this.certChain = certChain;
        this.conf = conf;
    }

    @Override
    public boolean isFinal() {
        return true;
    }

    @Override
    public CertificateGetterState nextState() {
        //try for renewal
        return new CheckRenewalState(kp, accountLocation, sslKeyPair, certChain, conf); 
    }

    public String getAccountLocation() {
        return accountLocation;
    }

    public void setAccountLocation(String accountLocation) {
        this.accountLocation = accountLocation;
    }

    @JSONPropertyIgnore
    public KeyPair getSslKeyPair() {
        return sslKeyPair;
    }

    public void setSslKeyPair(KeyPair sslKeyPair) {
        this.sslKeyPair = sslKeyPair;
    }

    @JSONPropertyIgnore
    public X509Certificate[] getCertChain() {
        return certChain;
    }

    public void setCertChain(X509Certificate[] certChain) {
        this.certChain = certChain;
    }

    @JSONPropertyIgnore
    public ConfBean getConf() {
        return conf;
    }

    public void setConf(ConfBean conf) {
        this.conf = conf;
    }

}
