package me.rainma22.dillydally.handler;

import java.io.IOException;
import java.net.URL;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class PathRedirectHandler implements HttpHandler {
    private URL redirectTo;
    private boolean appendPath;

    public PathRedirectHandler(URL redirectTo, boolean appendPath) {
        this.redirectTo = redirectTo;
        this.appendPath = appendPath;
    }

    @Override
    public void handle(HttpExchange exch) throws IOException {
        try {
            exch.getResponseHeaders().add("Location",
                    appendPath ? new URL(redirectTo, exch.getRequestURI().getPath()).toString()
                            : redirectTo.toString());
            exch.sendResponseHeaders(307, -1);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            exch.close();
        }
    }
}
