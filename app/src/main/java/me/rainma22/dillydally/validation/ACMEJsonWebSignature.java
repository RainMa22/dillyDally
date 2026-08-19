package me.rainma22.dillydally.validation;

import java.security.Key;
import java.util.Map;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.json.JSONObject;

public class ACMEJsonWebSignature extends JsonWebSignature {
    public ACMEJsonWebSignature(String accountLocation, String nonce, String url, Key SigningKey) {
        super();
        setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        setHeader("kid", accountLocation);
        setHeader("nonce", nonce);
        setHeader("url", url);
        setKey(SigningKey);
    }

    public ACMEJsonWebSignature(JsonWebKey jwk, String nonce, String url, Key SigningKey) {
        super();
        setAlgorithmHeaderValue(AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        setHeader("nonce", nonce);
        setHeader("url", url);
        setJwkHeader((PublicJsonWebKey) jwk);
        setKey(SigningKey);
    }

    public JSONObject toJson() throws JoseException {
        var segments = getCompactSerialization().split("[.]");
        var reqBody = new JSONObject(
                Map.of("protected", segments[0],
                        "payload", segments[1],
                        "signature", segments[2]));
        return reqBody;
    }
}
