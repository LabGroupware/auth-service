package org.cresplanex.account.oauth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.cresplanex.account.oauth.utils.OriginalAutoGenerate;

import java.time.LocalDate;

@Entity
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "accounts")
public class AccountEntity extends BaseEntity {

    @Id
    @OriginalAutoGenerate
    @Column(name = "account_id", length = 100, nullable = false, unique = true)
    private String accountId;

    @Version
    @Column(name = "version", nullable = false)
    private Integer version;

    @Column(name = "login_id", length = 200, nullable = false, unique = true)
    private String loginId;

    @Column(name = "password_hash", length = 200, nullable = false)
    private String passwordHash;

    @Column(name = "role", length = 100, nullable = false)
    private String role;

    @OneToOne(mappedBy = "account", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private UserEntity user;
}
