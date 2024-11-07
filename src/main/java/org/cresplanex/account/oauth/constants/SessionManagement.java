package org.cresplanex.account.oauth.constants;

public class SessionManagement {

    // 同時ログイン数
    public static final int MAXIMUM_SESSIONS = 3;

    // 同時ログインが発生した場合、新しいログインを許可するかどうか
    public static final boolean MAX_SESSIONS_PREVENTS_LOGIN = true;
}
