package me.rainma22.dillydally.validation;

import java.util.List;

import org.json.JSONPropertyName;

public class OrderChallenge {
    private String type;
    private String url;
    private String status;
    private String token = null;
    private String validated = null;
    private List<String> issuerDomainNames = null;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getValidated() {
        return validated;
    }

    public void setValidated(String validated) {
        this.validated = validated;
    }

    @JSONPropertyName("issuer-domain-names")
    public List<String> getIssuerDomainNames() {
        return issuerDomainNames;
    }

    @JSONPropertyName("issuer-domain-names")
    public void setIssuerDomainNames(List<String> issuerDomainNames) {
        this.issuerDomainNames = issuerDomainNames;
    }

}
