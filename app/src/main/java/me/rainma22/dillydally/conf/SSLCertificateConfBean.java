package me.rainma22.dillydally.conf;

import org.apache.commons.lang3.RandomStringUtils;

public class SSLCertificateConfBean {
    private static final RandomStringUtils random = RandomStringUtils.secureStrong();
    private String type = "file";
    private String pathToWebRootDir = "res/static";
    private int nPollingRetries = 10;
    private String pathToACMEPEM = "config/acme.pem";
    private String pathToSSLKeyPEM = "config/key.pem";
    private String pathToSSLCertPEM = "config/cert.pem";
    private int renewalThresholdInDays = 5;

    private String acmePassword = random.nextAlphanumeric(22);
    private String sslKeyPassword = random.nextAlphanumeric(22);

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getPathToWebRootDir() {
        return pathToWebRootDir;
    }

    public void setPathToWebRootDir(String pathToWebRootDir) {
        this.pathToWebRootDir = pathToWebRootDir;
    }

    public int getnPollingRetries() {
        return nPollingRetries;
    }

    public void setnPollingRetries(int nPollingRetries) {
        this.nPollingRetries = nPollingRetries;
    }

    public String getAcmePassword() {
        return acmePassword;
    }

    public void setAcmePassword(String acmePassword) {
        this.acmePassword = acmePassword;
    }

    public String getSslKeyPassword() {
        return sslKeyPassword;
    }

    public void setSslKeyPassword(String sslKeyPassword) {
        this.sslKeyPassword = sslKeyPassword;
    }

    public static RandomStringUtils getRandom() {
        return random;
    }

    public String getPathToACMEPEM() {
        return pathToACMEPEM;
    }

    public void setPathToACMEPEM(String pathToACMEPEM) {
        this.pathToACMEPEM = pathToACMEPEM;
    }

    public String getPathToSSLKeyPEM() {
        return pathToSSLKeyPEM;
    }

    public void setPathToSSLKeyPEM(String pathToSSLP12) {
        this.pathToSSLKeyPEM = pathToSSLP12;
    }

    public String getPathToSSLCertPEM() {
        return pathToSSLCertPEM;
    }

    public void setPathToSSLCertPEM(String pathToSSLCertPEM) {
        this.pathToSSLCertPEM = pathToSSLCertPEM;
    }

    public int getRenewalThresholdInDays() {
        return renewalThresholdInDays;
    }

    public void setRenewalThresholdInDays(int renewalThresholdInDays) {
        this.renewalThresholdInDays = renewalThresholdInDays;
    }

}
