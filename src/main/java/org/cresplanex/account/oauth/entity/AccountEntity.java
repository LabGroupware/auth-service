package org.cresplanex.account.oauth.entity;

import jakarta.persistence.*;
import lombok.*;
import org.cresplanex.api.state.common.entity.BaseEntity;
import org.cresplanex.api.state.common.utils.OriginalAutoGenerate;

@Entity
@Getter
@Setter
@ToString
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "accounts")
public class AccountEntity extends BaseEntity {

    @Override
    public void setId(String id) {
        this.accountId = id;
    }

    @Override
    public String getId() {
        return this.accountId;
    }

    @Id
    @OriginalAutoGenerate
    @Column(name = "account_id", length = 100, nullable = false, unique = true)
    private String accountId;

    @Column(name = "login_id", length = 200, nullable = false, unique = true)
    private String loginId;

    @Column(name = "password_hash", length = 200, nullable = false)
    private String passwordHash;

    @Column(name = "role", length = 100, nullable = false)
    private String role;

    @OneToOne(mappedBy = "account", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private UserEntity user;
}
