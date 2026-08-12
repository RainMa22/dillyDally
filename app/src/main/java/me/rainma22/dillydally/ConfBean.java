package me.rainma22.dillydally;

/**
 *
 */
public class ConfBean {
    private int lastRenew = 0;
    private int httpPort = 80;
    private int httpsPort = 443;
    private boolean staging = true;

    public int getLastRenew() {
        return lastRenew;
    }

    public void setLastRenew(int lastRenew) {
        this.lastRenew = lastRenew;
    }

    public int getHttpPort() {
        return httpPort;
    }

    public void setHttpPort(int httpPort) {
        this.httpPort = httpPort;
    }

    public int getHttpsPort() {
        return httpsPort;
    }

    public void setHttpsPort(int httpsPort) {
        this.httpsPort = httpsPort;
    }

    public boolean isStaging() {
        return staging;
    }

    public void setStaging(boolean staging) {
        this.staging = staging;
    }
    
}
