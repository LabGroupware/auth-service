package org.cresplanex.account.oauth.dto.oauth2RegisteredClient;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.cresplanex.account.oauth.constants.Scope;
import org.cresplanex.account.oauth.validate.Enum.ValidEnumList;

import java.util.List;

@Data
public class Oauth2RegisteredClientRequestDto {

    @NotEmpty
    private String clientId; // クライアントID

    private String clientSecret; // クライアントシークレット（オプション）

    @NotEmpty
    private String clientName; // クライアント名

    @NotEmpty
    private List<String> clientAuthenticationMethods; // 認証方法のリスト

    @NotEmpty
    private List<String> authorizationGrantTypes; // 認可グラントタイプのリスト

    @NotEmpty
    @ValidEnumList(enumClass = Scope.Type.class, message = "Invalid value. This must match one of the allowed enum values.")
    private List<String> scopes; // スコープのリスト

    private List<String> redirectUris; // リダイレクトURIのリスト

    private List<String> postLogoutRedirectUris; // ログアウト後のリダイレクトURI
}
