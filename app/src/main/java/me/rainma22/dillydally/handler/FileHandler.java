package me.rainma22.dillydally.handler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

public class FileHandler implements HttpHandler {
    private Path fileDir;

    public FileHandler(Path fileDir) {
        this.fileDir = fileDir.toAbsolutePath();
    }

    @Override
    public void handle(HttpExchange exch) throws IOException {
        try {
            Path path = fileDir
                    .resolve(Path.of(".", exch.getRequestURI().getPath().replaceFirst("/", "")));
            // System.out.print(exch.getRequestURI().getPath() + ": ");
            // System.out.println(path.toAbsolutePath().toString());
            if (!path.toAbsolutePath().startsWith(fileDir)) {
                exch.sendResponseHeaders(400, 0);
                return;
            } else {
                if (!Files.exists(path)) {
                    exch.getResponseHeaders().set("Content-Type", "text/html");
                    byte[] res = "<h1>Not Found</h1>".getBytes();

                    exch.sendResponseHeaders(404, res.length);
                    exch.getResponseBody().write(res);
                    return;
                }
                if (Files.isDirectory(path)) {
                    exch.getResponseHeaders().set("Content-Type", "text/html");
                    byte[] res = Files.list(path)
                            .sorted((p1, p2) -> {
                                if (Files.isDirectory(p1) && !Files.isDirectory(p2)) {
                                    return -1;
                                } else if (!Files.isDirectory(p1) && Files.isDirectory(p2)) {
                                    return 1;
                                } else {
                                    return p1.compareTo(p2);
                                }
                            })
                            .map(p -> {
                                String pathString = path.toAbsolutePath().relativize(p.toAbsolutePath())
                                        .toString();
                                boolean isFolder = Files.isDirectory(p);
                                return pathString.concat(isFolder ? "/" : "");
                            })
                            // .peek(System.out::println)
                            .map(s -> String.format("<li><a href=%s>%s</a></li>", s, s))
                            .reduce("<!DOCTYPE HTML>\n<html><body><ul>",
                                    String::concat)
                            .concat("</ul></body></html>").getBytes(StandardCharsets.UTF_8);
                    exch.sendResponseHeaders(200, res.length);
                    exch.getResponseBody().write(res);
                    return;
                } else {
                    String contentType = Files.probeContentType(path);
                    if (contentType != null) {
                        exch.getResponseHeaders().set("Content-Type", contentType);
                    }
                    try (var in = path.toUri().toURL().openStream()) {
                        exch.sendResponseHeaders(200, in.available());
                        in.transferTo(exch.getResponseBody());
                    }
                    return;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            exch.close();
        }
    }
}
