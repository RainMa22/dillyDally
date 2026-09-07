package me.rainma22.dillydally.handler;

import java.io.IOException;
import java.net.URI;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class ProtocolRedirectHandler implements HttpHandler {
    private String protocol;
    private Integer port;

    public ProtocolRedirectHandler(String protocol) {
        this(protocol, null);
    }

    public ProtocolRedirectHandler(String protocol, Integer port) {
        this.protocol = protocol;
        this.port = port;
    }

    @Override
    public void handle(HttpExchange exch) throws IOException {
        try {
            var hostUrl = URI.create("scheme://" + exch.getRequestHeaders().getFirst("Host"));
            var uriOut = new URI(protocol,
                    null,
                    hostUrl.getHost(),
                    port == null ? hostUrl.getPort() : port,
                    exch.getRequestURI().getPath(),
                    null, null);
            System.out.println(uriOut);
            exch.getResponseHeaders().add("Location", uriOut.toString());
            exch.sendResponseHeaders(307, -1);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            exch.close();
        }
    }
}
