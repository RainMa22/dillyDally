package me.rainma22.dillydally.conf;

public class HttpChallengeConfBean {
    private String type = "file";
    private String pathToWebRootDir = "res/static";
    private int nPollingRetries = 10;

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

}
