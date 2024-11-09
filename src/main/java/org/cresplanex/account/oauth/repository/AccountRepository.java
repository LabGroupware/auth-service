package org.cresplanex.account.oauth.repository;

import io.lettuce.core.dynamic.annotation.Param;
import org.cresplanex.account.oauth.entity.AccountEntity;
import org.cresplanex.account.oauth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<AccountEntity, String> {

    Optional<AccountEntity> findByLoginId(String loginId);

    @Query("SELECT a.user FROM AccountEntity a WHERE a.loginId = :loginId")
    Optional<UserEntity> findUserByLoginId(@Param("loginId") String loginId);
}
