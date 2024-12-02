package org.cresplanex.account.oauth.constants;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class SupportAuthorizationGrantType {
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String PASSWORD = "password";
    public static final String JWT_BEARER = "jwt-bearer";
    public static final String DEVICE_CODE = "device_code";
    public static final String TOKEN_EXCHANGE = "token-exchange";

    public static final String[] SUPPORTED_AUTHORIZATION_GRANT_TYPES = {
            AUTHORIZATION_CODE,
            REFRESH_TOKEN,
            CLIENT_CREDENTIALS,
            PASSWORD,
            JWT_BEARER,
            DEVICE_CODE,
            TOKEN_EXCHANGE
    };
}
