package me.rainma22.dillydally.validation;

import io.jsonwebtoken.JwtBuilder;

public class Utils {
        public static String JSONStringof(JwtBuilder sig) {
                return ACMEJWS.toJson(sig).toString(4);
        }

}
