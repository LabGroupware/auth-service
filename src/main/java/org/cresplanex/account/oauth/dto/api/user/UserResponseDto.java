package org.cresplanex.account.oauth.dto.api.user;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serial;
import java.io.Serializable;

@Data
@AllArgsConstructor
public class UserResponseDto implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String userId;             // ユーザーID
    private String name;               // フルネーム
    private String email;              // メールアドレス
    private String givenName;          // 名前（名）
    private String familyName;         // 名前（姓）
    private String middleName;         // ミドルネーム
    private String nickname;           // ニックネーム
    private String preferredUsername;  // 推奨ユーザー名
    private String address;            // 住所
    private String profile;            // プロフィール
    private String picture;            // プロフィール画像
    private String website;            // ウェブサイト
    private String phone;              // 電話番号
    private String gender;          // 性別
    private String birthdate;       // 誕生日
    private String zoneinfo;           // タイムゾーン情報
    private String locale;             // 言語ロケール
}
