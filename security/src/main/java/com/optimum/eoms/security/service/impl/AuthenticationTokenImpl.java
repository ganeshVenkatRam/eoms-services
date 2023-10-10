package com.optimum.eoms.security.service.impl;

import com.optimum.eoms.security.util.SessionUser;
import java.util.Collection;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.DigestUtils;

/** used to provide security authentication object */
@Slf4j
public class AuthenticationTokenImpl extends AbstractAuthenticationToken {
  String username;

  public AuthenticationTokenImpl(
      String username, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.username = username;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return username != null ? username : "";
  }

  /**
   * used to generate hash value to store in redis cache
   *
   * @return generated hash value
   */
  public String getHash() {
    log.info("into getHash()");
    return DigestUtils.md5DigestAsHex(
        String.format("%s_%d", username, ((SessionUser) getDetails()).getCreated().getTime())
            .getBytes());
  }
}
