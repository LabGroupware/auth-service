package org.cresplanex.account.oauth.repository;

import org.cresplanex.account.oauth.entity.Oauth2RegisteredClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface Oauth2RegisteredClientRepository extends JpaRepository<Oauth2RegisteredClientEntity, String> {

    Optional<Oauth2RegisteredClientEntity> findByClientId(String clientId);
}
