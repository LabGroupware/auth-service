package org.cresplanex.account.oauth.exception;

import lombok.Getter;
import lombok.Setter;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;

@Getter @Setter
public class UserDuplicateException extends ServiceException {

    private final UniqueType uniqueType;
    private final Object uniqueValue;

    public UserDuplicateException(UniqueType uniqueType, Object uniqueValue) {
        this(uniqueType, uniqueValue, "Duplicated: " + uniqueType.name() + " with " + uniqueValue);
    }

    public UserDuplicateException(UniqueType uniqueType, Object uniqueValue, String message) {
        super(message);
        this.uniqueType = uniqueType;
        this.uniqueValue = uniqueValue;
    }

    public UserDuplicateException(UniqueType uniqueType, Object uniqueValue, String message, Throwable cause) {
        super(message, cause);
        this.uniqueType = uniqueType;
        this.uniqueValue = uniqueValue;
    }

    public enum UniqueType {
        EMAIL,
        USER_ID
    }

    @Override
    public AuthServerError getErrorCode() {
        return new AuthServerError(AuthServerErrorCode.ACCOUNT_ALREADY_EXISTS, getErrorCaption());
    }

    public String getErrorCaption() {
        return switch (uniqueType) {
            case EMAIL -> "Account Duplicated (Email = %s)".formatted(uniqueValue);
            case USER_ID -> "Account Duplicated (USER_ID = %s)".formatted(uniqueValue);
            default -> "Account Duplicated";
        };
    }
}
