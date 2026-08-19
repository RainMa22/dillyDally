package me.rainma22.dillydally.conf;

import java.util.List;

/**
 *
 */
public class ConfBean {
    private int lastRenew = 0;
    private int httpPort = 80;
    private int httpsPort = 443;
    private boolean staging = true;
    private HttpChallengeConfBean httpChallengeConf = new HttpChallengeConfBean();

    private List<String> domains = List.of(
            "this.is.a.test.com");

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

    public List<String> getDomains() {
        return domains;
    }

    public void setDomains(List<String> domains) {
        this.domains = domains;
    }

    public HttpChallengeConfBean getHttpChallengeConf() {
        return httpChallengeConf;
    }

    public void setHttpChallengeConf(HttpChallengeConfBean httpChallengeConf) {
        this.httpChallengeConf = httpChallengeConf;
    }

}
