package org.cresplanex.account.oauth.exception;

import lombok.Getter;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;

@Getter
public class AuthServerError {

    private final String code;
    private final String message;

    public AuthServerError() {
        this(AuthServerErrorCode.INTERNAL_SERVER_ERROR, "Internal Server Error");
    }

    public AuthServerError(String code, String message) {
        this.code = code;
        this.message = message;
    }

}
