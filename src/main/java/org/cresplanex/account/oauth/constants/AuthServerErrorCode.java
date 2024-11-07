package org.cresplanex.account.oauth.constants;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Map;

@AllArgsConstructor
public class AuthServerErrorCode {

    public static final String SUCCESS = "0000";
    public static final String INTERNAL_SERVER_ERROR = "1000";
    public static final String ACCOUNT_ALREADY_EXISTS = "1001";
    public static final String USER_ALREADY_EXISTS = "1002";
    public static final String VALIDATION_ERROR = "1003";
    public static final String METHOD_NOT_ALLOWED = "1004";
    public static final String NOT_SUPPORT_CONTENT_TYPE = "1005";
    public static final String AUTHENTICATION_FAILED = "1006";
    public static final String AUTHORIZATION_FAILED = "1007";
    public static final String ACCESS_DENIED = "1008";
    public static final String METHOD_ARGUMENT_TYPE_MISMATCH = "1009";
    public static final String MISSING_PATH_VARIABLE = "1010";
    public static final String EXCEED_MAX_UPLOAD_SIZE = "1011";
    public static final String NOT_FOUND_HANDLER = "1012";
    public static final String NOT_READABLE_REQUEST = "1013";
    public static final String INVALID_OPAQUE_TOKEN = "1014";
    public static final String INVALID_ACCESS_TOKEN = "1015";
}
