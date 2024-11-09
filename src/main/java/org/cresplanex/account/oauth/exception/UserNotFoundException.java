package org.cresplanex.account.oauth.exception;

import lombok.Getter;
import lombok.Setter;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;

@Getter @Setter
public class UserNotFoundException extends ServiceException {

    private final FindType findType;
    private final Object findValue;

    public UserNotFoundException(FindType findType, Object findValue) {
        this(findType, findValue, "Not Found: " + findType.name() + " with " + findValue);
    }

    public UserNotFoundException(FindType findType, Object findValue, String message) {
        super(message);
        this.findType = findType;
        this.findValue = findValue;
    }

    public UserNotFoundException(FindType findType, Object findValue, String message, Throwable cause) {
        super(message, cause);
        this.findType = findType;
        this.findValue = findValue;
    }

    public enum FindType {
        EMAIL,
        USER_ID
    }

    @Override
    public AuthServerError getErrorCode() {
        return new AuthServerError(AuthServerErrorCode.USER_NOT_FOUND, getErrorCaption());
    }

    public String getErrorCaption() {
        return switch (findType) {
            case EMAIL -> "User Not Found (Email = %s)".formatted(findValue);
            case USER_ID -> "User Not Found (USER_ID = %s)".formatted(findValue);
            default -> "User Not Found";
        };
    }
}
