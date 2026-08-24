package me.rainma22.dillydally.sslcert;

import java.util.List;

public class AuthChallengeResponse {
    private String status;
    private String expires;
    private OrderIdentifier identifier;
    private List<OrderChallenge> challenges;

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

    public OrderIdentifier getIdentifier() {
        return identifier;
    }

    public void setIdentifier(OrderIdentifier identifier) {
        this.identifier = identifier;
    }

    public List<OrderChallenge> getChallenges() {
        return challenges;
    }

    public void setChallenges(List<OrderChallenge> challenges) {
        this.challenges = challenges;
    }

}
