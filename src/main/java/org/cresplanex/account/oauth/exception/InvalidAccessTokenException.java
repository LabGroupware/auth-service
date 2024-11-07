package org.cresplanex.account.oauth.exception;

import lombok.Getter;
import lombok.Setter;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;

@Getter @Setter
public class InvalidAccessTokenException extends ServiceException {

    public InvalidAccessTokenException(String message) {
        super(message);
    }

    public InvalidAccessTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public AuthServerError getErrorCode() {
        return new AuthServerError(AuthServerErrorCode.INVALID_ACCESS_TOKEN, "Invalid access token.");
    }
}
