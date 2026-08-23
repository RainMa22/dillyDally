package me.rainma22.dillydally.validation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;

import io.jsonwebtoken.JwtBuilder;

public class Utils {

        public static boolean webAccessible(URI uri) {
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

        public static String JSONStringof(JwtBuilder sig) {
                return ACMEJWS.toJson(sig).toString(4);
        }

}
