package com.optimum.eoms.security.repository;

import com.optimum.eoms.security.entity.UserToken;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/** used to declare repository for token table to make token related DB calls */
@Repository
public interface UserTokenRepository extends JpaRepository<UserToken, Integer> {

  Optional<UserToken> findByAccessToken(String accessToken);
}
