package org.cresplanex.account.oauth.constants;

import org.springframework.beans.factory.annotation.Value;

public class JwtSettings {
    public static final String JWT_SECRET_KEY = "JWT_SECRET";
    public static final String JWT_SECRET_DEFAULT_VALUE = "jxgEQeXHuPq8VdbyYFNkANdudQ53YUn4";
    public static final String JWT_HEADER = "Authorization";

    public static final String JWT_TOKEN_DEFAULT_ISSUER = "issuer";
    public static final long JWT_TOKEN_DEFAULT_EXPIRATION = 30000000;

    public static final long JWT_OPAQUE_TOKEN_EXCHANGE_EXPIRATION = 300;
}
