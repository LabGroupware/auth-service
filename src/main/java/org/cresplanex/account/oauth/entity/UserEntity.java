package org.cresplanex.account.oauth.entity;

import java.time.LocalDate;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.cresplanex.account.oauth.utils.OriginalAutoGenerate;

@Entity
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "users")
public class UserEntity extends BaseEntity {

    @Id
    @OriginalAutoGenerate
    @Column(name = "user_id", length = 100, nullable = false, unique = true)
    private String userId;

    @Version
    @Column(name = "version", nullable = false)
    private Integer version;

    @Column(name = "name", length = 200, nullable = false)
    private String name;

    @Column(name = "email", length = 200, nullable = false)
    private String email;

    @Column(name = "given_name", length = 100)
    private String givenName;

    @Column(name = "family_name", length = 100)
    private String familyName;

    @Column(name = "middle_name", length = 100)
    private String middleName;

    @Column(name = "nickname", length = 100)
    private String nickname;

    @Column(name = "preferred_username", length = 100)
    private String preferredUsername;

    @Lob
    @Column(name = "address")
    private String address;

    @Lob
    @Column(name = "profile")
    private String profile;

    @Lob
    @Column(name = "picture")
    private String picture;

    @Lob
    @Column(name = "website")
    private String website;

    @Column(name = "phone", length = 15)
    private String phone;

    @Column(name = "gender", length = 1)
    private String gender;

    @Column(name = "birthdate")
    private LocalDate birthdate;

    @Column(name = "zoneinfo", length = 50)
    private String zoneinfo;

    @Column(name = "locale", length = 10)
    private String locale;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "account_id", referencedColumnName = "account_id", nullable = false, unique = true)
    private AccountEntity account;
}
