package org.cresplanex.account.oauth.constants;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

public class SupportClientAuthenticationMethods {

    public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
    public static final String CLIENT_SECRET_POST = "client_secret_post";
    public static final String CLIENT_SECRET_JWT = "client_secret_jwt";
    public static final String PRIVATE_KEY_JWT = "private_key_jwt";
    public static final String NONE = "none";
    public static final String TLS_CLIENT_AUTH = "tls_client_auth";
    public static final String SELF_SIGNED_TLS_CLIENT_AUTH = "self_signed_tls_client_auth";

    public static final String[] SUPPORTED_CLIENT_AUTHENTICATION_METHODS = {
            CLIENT_SECRET_BASIC,
            CLIENT_SECRET_POST,
            CLIENT_SECRET_JWT,
            PRIVATE_KEY_JWT,
            NONE,
            TLS_CLIENT_AUTH,
            SELF_SIGNED_TLS_CLIENT_AUTH
    };
}
