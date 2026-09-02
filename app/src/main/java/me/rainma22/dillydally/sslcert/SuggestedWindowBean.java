package me.rainma22.dillydally.sslcert;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class SuggestedWindowBean {
    private String notBefore = DateTimeFormatter.ISO_DATE_TIME.format(LocalDateTime.MAX);
    private String notAfter = DateTimeFormatter.ISO_DATE_TIME.format(LocalDateTime.MIN);

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

}
