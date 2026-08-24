package me.rainma22.dillydally.sslcert;

import java.security.Key;
import java.util.Map;

import org.json.JSONObject;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwk;

public class ACMEJWS {
    public static JwtBuilder withAccountLocation(String accountLocation, String nonce, String url, Key SigningKey) {
        return Jwts.builder().header()
                .add("kid", accountLocation)
                .add("nonce", nonce)
                .add("url", url)
                .and()
                .signWith(SigningKey);
    }

    public static JwtBuilder withJWK(Jwk<?> jwk, String nonce, String url, Key SigningKey) {
        return Jwts.builder()
                .header().add("jwk", jwk)
                .add("nonce", nonce)
                .add("url", url)
                .and()
                .signWith(SigningKey);
    }

    public static JSONObject toJson(String compacted) {
        var segments = compacted.split("[.]");
        var reqBody = new JSONObject(
                Map.of("protected", segments[0],
                        "payload", segments[1],
                        "signature", segments[2]));
        return reqBody;
    }

    public static JSONObject toJson(JwtBuilder jws) {
        return toJson(jws.compact());
    }

    public static String toString(JwtBuilder jws){
        return toJson(jws).toString();
    }
}
