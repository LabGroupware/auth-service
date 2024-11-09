package org.cresplanex.account.oauth.constants;

import org.springframework.security.oauth2.core.oidc.OidcScopes;

public class Scope {

    public static final String OPENID = OidcScopes.OPENID;
    public static final String PROFILE = OidcScopes.PROFILE;
    public static final String EMAIL = OidcScopes.EMAIL;
    public static final String ADDRESS = OidcScopes.ADDRESS;
    public static final String PHONE = OidcScopes.PHONE;

    public static final String READ = "read";
    public static final String WRITE = "write";

    public static final String[] ALLOWED_VALUES = { OPENID, PROFILE, EMAIL, ADDRESS, PHONE, READ, WRITE };
}
