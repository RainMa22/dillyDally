package me.rainma22.dillydally.validation;

import java.util.List;

import org.json.JSONObject;

public class NewOrderResponse {
    String status;
    String expires;
    String notBefore = null;
    String notAfter = null;
    List<OrderIdentifier> identifiers;
    List<String> authorizations;
    String finalize;
    String certificate = null;
    JSONObject error = null;

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getExpires() {
        return expires;
    }

    public void setExpires(String expires) {
        this.expires = expires;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public List<OrderIdentifier> getIdentifiers() {
        return identifiers;
    }

    public void setIdentifiers(List<OrderIdentifier> identifiers) {
        this.identifiers = identifiers;
    }

    public List<String> getAuthorizations() {
        return authorizations;
    }

    public void setAuthorizations(List<String> authorizations) {
        this.authorizations = authorizations;
    }

    public String getFinalize() {
        return finalize;
    }

    public void setFinalize(String finalize) {
        this.finalize = finalize;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    public JSONObject getError() {
        return error;
    }

    public void setError(JSONObject error) {
        this.error = error;
    }

}
