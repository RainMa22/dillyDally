package me.rainma22.dillydally.sslcert.challengecompletion;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;

import io.jsonwebtoken.security.Jwks;
import me.rainma22.dillydally.conf.HttpChallengeConfBean;
import me.rainma22.dillydally.sslcert.OrderChallenge;

public class ChallengeCompletor {
    private HttpChallengeConfBean httpConf;

    public ChallengeCompletor(HttpChallengeConfBean httpChallengeConfBean) throws UnsupportedOperationException {
        httpConf = httpChallengeConfBean;
        if (!httpChallengeConfBean.getType().equalsIgnoreCase("file")) {
            throw new UnsupportedOperationException(
                    "unsupported challenge type configured: "
                            + httpChallengeConfBean.getType());
        }
    }

    public void completeChallenge(OrderChallenge challenge, KeyPair kp) throws IOException {
        var challengeFolderPath = Path.of(httpConf.getPathToWebRootDir(), ".well-known",
                "acme-challenge");
        Files.createDirectories(challengeFolderPath);
        var challengeFilePath = challengeFolderPath.resolve(challenge.getToken());
        var thumbprint = Jwks.builder().key(kp.getPublic()).build()
                .thumbprint(Jwks.HASH.SHA256).toString()
                .replaceAll("=", "");
        Files.createFile(challengeFilePath);
        Files.writeString(challengeFilePath, challenge.getToken() + "." + thumbprint);
        // System.out.printf("finished putting %s at %s/.well-known/acme-challenge/%s
        // \n",
        // challenge.getToken(),
        // httpConf.getPathToWebRootDir(),
        // challenge.getToken());
    }

    public boolean isUriAccessible(URI uri) {
        try {
            var client = HttpClient.newBuilder()
                    .followRedirects(Redirect.ALWAYS)
                    .build();
            var req = HttpRequest.newBuilder(uri)
                    .GET()
                    .build();
            return client.send(req, BodyHandlers.ofString())
                    .statusCode() == 200;
        } catch (IOException e) {
            // ignored
        } catch (InterruptedException e) {
            // ignored
        }
        return false;
    }
}
