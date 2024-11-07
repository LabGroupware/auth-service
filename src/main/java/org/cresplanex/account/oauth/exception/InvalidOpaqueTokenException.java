package org.cresplanex.account.oauth.exception;

import lombok.Getter;
import lombok.Setter;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;

@Getter @Setter
public class InvalidOpaqueTokenException extends ServiceException {

    public InvalidOpaqueTokenException(String message) {
        super(message);
    }

    public InvalidOpaqueTokenException(String message, Throwable cause) {
        super(message, cause);
    }

    @Override
    public AuthServerError getErrorCode() {
        return new AuthServerError(AuthServerErrorCode.INVALID_OPAQUE_TOKEN, "Invalid opaque token.");
    }
}
