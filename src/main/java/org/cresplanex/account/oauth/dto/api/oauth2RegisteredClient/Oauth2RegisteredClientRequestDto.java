package org.cresplanex.account.oauth.dto.api.oauth2RegisteredClient;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.cresplanex.account.oauth.validate.List.AllowedAuthenticationMethods;
import org.cresplanex.account.oauth.validate.List.AllowedGrantTypes;
import org.cresplanex.account.oauth.validate.List.AllowedScopeValues;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

@Data
public class Oauth2RegisteredClientRequestDto implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @NotEmpty
    private String clientName; // クライアント名

    @NotEmpty
    @AllowedAuthenticationMethods(message = "Value must be one of the following: 'client_secret_basic', 'client_secret_post', 'client_secret_jwt', 'private_key_jwt', 'none', 'tls_client_auth', 'self_signed_tls_client_auth'")
    private List<String> clientAuthenticationMethods; // 認証方法のリスト

    @NotEmpty
    @AllowedGrantTypes(message = "Value must be one of the following: 'authorization_code', 'refresh_token', 'client_credentials', 'password', 'jwt-bearer', 'device_code', 'token-exchange'")
    private List<String> authorizationGrantTypes; // 認可グラントタイプのリスト

    @AllowedScopeValues(message = "Value must be one of the following: 'openid', 'profile', 'email', 'address', 'phone'")
    private List<String> scopes; // スコープのリスト

    @NotEmpty
    private List<String> redirectUris; // リダイレクトURIのリスト

    private List<String> postLogoutRedirectUris; // ログアウト後のリダイレクトURI
}
