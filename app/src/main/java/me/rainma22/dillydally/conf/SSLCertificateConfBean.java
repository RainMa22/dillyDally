package me.rainma22.dillydally.conf;

import org.apache.commons.lang3.RandomStringUtils;

public class SSLCertificateConfBean {
    private static final RandomStringUtils random = RandomStringUtils.secureStrong();
    private String type = "file";
    private String pathToWebRootDir = "res/static";
    private int nPollingRetries = 10;
    private String pathToACMEPEM = "config/acme.pem";
    private String pathToSSLP12 = "config/ssl.p12";
    private String acmePassword = random.nextAlphanumeric(22);
    private String sslKeyPassword = random.nextAlphanumeric(22);
    private String keyStorePassword = random.nextAlphanumeric(22);

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

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String sslKeyStorePassword) {
        this.keyStorePassword = sslKeyStorePassword;
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

    public String getPathToSSLP12() {
        return pathToSSLP12;
    }

    public void setPathToSSLP12(String pathToSSLP12) {
        this.pathToSSLP12 = pathToSSLP12;
    }

}
