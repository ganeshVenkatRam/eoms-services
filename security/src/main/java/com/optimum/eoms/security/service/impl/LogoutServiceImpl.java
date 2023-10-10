package com.optimum.eoms.security.service.impl;

import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.entity.UserToken;
import com.optimum.eoms.security.repository.UserTokenRepository;
import com.optimum.eoms.security.service.JwtService;
import com.optimum.eoms.security.service.RedisService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogoutServiceImpl implements LogoutHandler {

  @Autowired JwtService jwtService;

  @Autowired RedisService redisService;

  @Autowired UserTokenRepository userTokenRepository;

  @Override
  public void logout(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

    try {
      String token = jwtService.parseToken(request);
      if (token != null) {
        Claims claims = jwtService.getClaims(token);
        if (claims != null && claims.get(SecurityConstants.USER_NAME) != null) {
          String username = claims.get(SecurityConstants.USER_NAME).toString();
          String hashKeyClaim = claims.get(SecurityConstants.HASH).toString();
          Optional<UserToken> userToken = userTokenRepository.findByAccessToken(token);
          if (userToken.isPresent()) {
            UserToken accessToken = userToken.get();
            if (!accessToken.getExpired()) {
              accessToken.setExpired(true);
              UserToken accessTokenUpdate = userTokenRepository.save(accessToken);
              if (accessTokenUpdate != null) {
                redisService.removeHashValue(
                    String.format("%s:%s", username.toLowerCase(), hashKeyClaim), hashKeyClaim);
                response.setStatus(200);
                return;
              }
            }
          }
        }
      }
      response.setStatus(401);
    } catch (Exception exception) {
      response.setStatus(401);
    }
  }
}
