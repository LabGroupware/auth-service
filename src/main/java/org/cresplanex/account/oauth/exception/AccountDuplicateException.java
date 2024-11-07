package org.cresplanex.account.oauth.exception;

import lombok.Getter;
import lombok.Setter;
import org.cresplanex.account.oauth.constants.AuthServerErrorCode;

@Getter @Setter
public class AccountDuplicateException extends ServiceException {

    private final UniqueType uniqueType;
    private final Object uniqueValue;

    public AccountDuplicateException(UniqueType uniqueType, Object uniqueValue) {
        this(uniqueType, uniqueValue, "Duplicated: " + uniqueType.name() + " with " + uniqueValue);
    }

    public AccountDuplicateException(UniqueType uniqueType, Object uniqueValue, String message) {
        super(message);
        this.uniqueType = uniqueType;
        this.uniqueValue = uniqueValue;
    }

    public AccountDuplicateException(UniqueType uniqueType, Object uniqueValue, String message, Throwable cause) {
        super(message, cause);
        this.uniqueType = uniqueType;
        this.uniqueValue = uniqueValue;
    }

    public enum UniqueType {
        LOGIN_ID,
        EMAIL,
        USER_ID
    }

    @Override
    public AuthServerError getErrorCode() {
        return new AuthServerError(AuthServerErrorCode.ACCOUNT_ALREADY_EXISTS, getErrorCaption());
    }

    public String getErrorCaption() {
        return switch (uniqueType) {
            case LOGIN_ID -> "Account Duplicated (LOGIN_ID = %s)".formatted(uniqueValue);
            case EMAIL -> "Account Duplicated (Email = %s)".formatted(uniqueValue);
            case USER_ID -> "Account Duplicated (USER_ID = %s)".formatted(uniqueValue);
            default -> "Account Duplicated";
        };
    }
}
