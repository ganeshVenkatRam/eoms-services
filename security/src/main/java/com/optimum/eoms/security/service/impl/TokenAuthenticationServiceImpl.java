package com.optimum.eoms.security.service.impl;

import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.entity.UserToken;
import com.optimum.eoms.security.repository.UserTokenRepository;
import com.optimum.eoms.security.service.JwtService;
import com.optimum.eoms.security.service.TokenAuthenticationService;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

/** used to provide implementations for authentication service methods */
@Slf4j
@Service
public class TokenAuthenticationServiceImpl implements TokenAuthenticationService {

  @Autowired JwtService jwtService;

  @Autowired UserTokenRepository userTokenRepository;

  /**
   * used to get authentication for the protected APIs for the user
   *
   * @param request
   * @return authentication
   */
  @Override
  public Authentication getAuthentication(HttpServletRequest request) throws JSONException {
    log.info("into getAuthentication()");
    String token = jwtService.parseToken(request);
    if (token != null) {
      Optional<UserToken> userToken = userTokenRepository.findByAccessToken(token);
      if (userToken.isPresent()) {
        UserToken accessToken = userToken.get();
        if (!accessToken.getExpired()) {
          Decoder decoder = Base64.getUrlDecoder();
          String jsonString = new String(decoder.decode((token.split("\\.")[0])));
          if (StringUtils.isNotEmpty(jsonString)) {
            JSONObject jsonObject = new JSONObject(jsonString);
            if (jsonObject.get("typ").toString().equals(SecurityConstants.ACCESS_TOKEN_TYPE)
                || jsonObject.get("typ").toString().equals(SecurityConstants.PASSWORD_TOKEN_TYPE)) {
              Map<String, Object> resultMap = jwtService.getUserInfo(token);
              if (resultMap.get(SecurityConstants.USER_INFO_RESULT) != null) {
                AuthenticationTokenImpl authenticationToken;
                if (resultMap.get(SecurityConstants.ROLES) != null) {
                  authenticationToken =
                      new AuthenticationTokenImpl(
                          resultMap.get(SecurityConstants.USER_NAME).toString(),
                          (Collection<? extends GrantedAuthority>)
                              resultMap.get(SecurityConstants.FUNCTIONS));
                } else {
                  authenticationToken =
                      new AuthenticationTokenImpl(
                          resultMap.get(SecurityConstants.USER_NAME).toString(), null);
                }

                authenticationToken.setDetails(resultMap.get(SecurityConstants.USER_INFO_RESULT));
                authenticationToken.setAuthenticated(
                    authenticationToken.getDetails() instanceof UserInfoDto);
                return authenticationToken;
              }
            }
          }
        }
      }
    }
    return new UsernamePasswordAuthenticationToken(null, null);
  }
}
