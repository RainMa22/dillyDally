package me.rainma22.dillydally.conf;

import java.util.List;

/**
 *
 */
public class ConfBean {
    private int httpPort = 80;
    private int httpsPort = 443;
    private String serverUrl = "https://acme-staging-v02.api.letsencrypt.org/directory";
    public String getServerUrl() {
        return serverUrl;
    }

    public void setServerUrl(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    private SSLCertificateConfBean sslCertificateConf = new SSLCertificateConfBean();

    private List<String> domains = List.of(
            "this.is.a.test.com");

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
    
    public List<String> getDomains() {
        return domains;
    }

    public void setDomains(List<String> domains) {
        this.domains = domains;
    }

    public SSLCertificateConfBean getSslCertificateConf() {
        return sslCertificateConf;
    }

    public void setSslCertificateConf(SSLCertificateConfBean sslCertificateConf) {
        this.sslCertificateConf = sslCertificateConf;
    }

}
