package me.rainma22.dillydally.sslcert;

import java.util.List;

import org.json.JSONPropertyIgnore;

/**
 *
 */
public class ResourceLocationResponse {
    // {
    // "newNonce": "https://example.com/acme/new-nonce",
    // "newAccount": "https://example.com/acme/new-account",
    // "newOrder": "https://example.com/acme/new-order",
    // "newAuthz": "https://example.com/acme/new-authz",
    // "revokeCert": "https://example.com/acme/revoke-cert",
    // "keyChange": "https://example.com/acme/key-change",
    // "meta": {
    // "termsOfService": "https://example.com/acme/terms/2017-5-30",
    // "website": "https://www.example.com/",
    // "caaIdentities": ["example.com"],
    // "externalAccountRequired": false
    // }
    // }

    private String newNonce, newAccount, newOrder, newAuthz, revokeCert, keyChange;
    private String renewalInfo = null;

    private Meta meta;

    public String getNewNonce() {
        return newNonce;
    }

    public void setNewNonce(String newNonce) {
        this.newNonce = newNonce;
    }

    public String getNewAccount() {
        return newAccount;
    }

    public void setNewAccount(String newAccount) {
        this.newAccount = newAccount;
    }

    public String getNewOrder() {
        return newOrder;
    }

    public void setNewOrder(String newOrder) {
        this.newOrder = newOrder;
    }

    public String getNewAuthz() {
        return newAuthz;
    }

    public void setNewAuthz(String newAuthz) {
        this.newAuthz = newAuthz;
    }

    public String getRevokeCert() {
        return revokeCert;
    }

    public void setRevokeCert(String revokeCert) {
        this.revokeCert = revokeCert;
    }

    public String getKeyChange() {
        return keyChange;
    }

    public void setKeyChange(String keyChange) {
        this.keyChange = keyChange;
    }

    public Meta getMeta() {
        return meta;
    }

    public void setMeta(Meta meta) {
        this.meta = meta;
    }

    public String getRenewalInfo() {
        return renewalInfo;
    }

    public void setRenewalInfo(String renewalInfo) {
        this.renewalInfo = renewalInfo;
    }

    @JSONPropertyIgnore
    public boolean isAIRSupported() {
        return getRenewalInfo() != null;
    }

    public static class Meta {

        private String termsOfService, website;
        private List<String> caaIdentities;
        boolean externalAccountRequired;

        public String getTermsOfService() {
            return termsOfService;
        }

        public void setTermsOfService(String termsOfService) {
            this.termsOfService = termsOfService;
        }

        public String getWebsite() {
            return website;
        }

        public void setWebsite(String website) {
            this.website = website;
        }

        public List<String> getCaaIdentities() {
            return caaIdentities;
        }

        public void setCaaIdentities(List<String> caaIdentities) {
            this.caaIdentities = caaIdentities;
        }

        public boolean isExternalAccountRequired() {
            return externalAccountRequired;
        }

        public void setExternalAccountRequired(boolean externalAccountRequired) {
            this.externalAccountRequired = externalAccountRequired;
        }

    }

}
