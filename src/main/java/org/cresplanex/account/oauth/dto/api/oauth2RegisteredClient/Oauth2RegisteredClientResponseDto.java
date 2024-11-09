package org.cresplanex.account.oauth.dto.api.oauth2RegisteredClient;

import lombok.Data;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class Oauth2RegisteredClientResponseDto implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String id; // サーバー側で生成される一意の識別子

    private String clientId; // クライアントID

    private LocalDateTime clientIdIssuedAt; // クライアントID発行日時

    private String clientName; // クライアント名

    private List<String> clientAuthenticationMethods; // 認証方法のリスト

    private List<String> authorizationGrantTypes; // 認可グラントタイプのリスト

    private List<String> scopes; // スコープのリスト

    private List<String> redirectUris; // リダイレクトURIのリスト

    private List<String> postLogoutRedirectUris; // ログアウト後のリダイレクトURI

    private LocalDateTime clientSecretExpiresAt; // クライアントシークレットの有効期限

    private String clientSettings; // JSON形式のクライアント設定

    private String tokenSettings; // JSON形式のトークン設定
}
