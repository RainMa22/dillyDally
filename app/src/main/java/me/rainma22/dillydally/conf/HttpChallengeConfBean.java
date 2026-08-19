package me.rainma22.dillydally.conf;

import java.io.File;

public class HttpChallengeConfBean {
    private String type = "file";
    private String pathToWebRootDir = "res/static";

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

}
