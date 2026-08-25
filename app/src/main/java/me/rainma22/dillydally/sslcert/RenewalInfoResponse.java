package me.rainma22.dillydally.sslcert;


public class RenewalInfoResponse {
    private SuggestedWindowBean suggestedWindow;
    private String explainationURL = null;

    public SuggestedWindowBean getSuggestedWindow() {
        return suggestedWindow;
    }

    public void setSuggestedWindow(SuggestedWindowBean suggestedWindow) {
        this.suggestedWindow = suggestedWindow;
    }

    public String getExplainationURL() {
        return explainationURL;
    }

    public void setExplainationURL(String explainationURL) {
        this.explainationURL = explainationURL;
    }

}
