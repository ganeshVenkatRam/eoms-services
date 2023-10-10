package com.optimum.eoms.security.service.impl;

import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.model.user.entity.User;
import com.optimum.eoms.model.user.repository.UserRepository;
import com.optimum.eoms.security.constants.SecurityConstants;
import com.optimum.eoms.security.dto.PasswordTokenDto;
import com.optimum.eoms.security.dto.RefreshTokenDto;
import com.optimum.eoms.security.dto.UserTokenDto;
import com.optimum.eoms.security.entity.UserToken;
import com.optimum.eoms.security.repository.UserTokenRepository;
import com.optimum.eoms.security.service.JwtService;
import com.optimum.eoms.security.service.RedisService;
import com.optimum.eoms.security.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

/** used to provide implementations for JWT service methods */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtServiceImpl extends LoginBaseServiceImpl implements JwtService {

  @Value("${eoms.app.secretKey}")
  private String secretKey;

  @Value("${eoms.app.jwtAccessExpirationMs}")
  private long jwtAccessTokenExpirationTime;

  @Value("${eoms.app.jwtRefreshExpirationMs}")
  private long jwtRefreshTokenExpirationTime;

  @Value("${eoms.app.jwtSetPasswordLinkExpirationMs}")
  private long jwtSetPasswordLinkExpirationMs;

  @Autowired RedisService redisService;

  @Autowired UserRepository userRepository;

  @Autowired UserTokenRepository userTokenRepository;

  /**
   * used to generate access token for valid user
   *
   * @param userSecurityDetailsDto
   * @param hashKey
   * @return
   */
  @Override
  public UserTokenDto generateAccessToken(
      UserSecurityDetailsDto userSecurityDetailsDto, String hashKey) {
    log.info("into generateAccessToken()");
    Map<String, Object> tokenMap =
        JwtUtil.generateToken(
            userSecurityDetailsDto,
            hashKey,
            jwtAccessTokenExpirationTime,
            secretKey,
            SecurityConstants.ACCESS_TOKEN_TYPE,
            SecurityConstants.ACCESS_TOKEN);
    return prepareTokenDto(userSecurityDetailsDto, tokenMap, SecurityConstants.ACCESS_TOKEN);
  }

  @Override
  public RefreshTokenDto generateRefreshToken(
      UserSecurityDetailsDto userSecurityDetailsDto, String hashKey) {
    log.info("into generateRefreshToken()");
    Map<String, Object> tokenMap =
        JwtUtil.generateToken(
            userSecurityDetailsDto,
            hashKey,
            jwtRefreshTokenExpirationTime,
            secretKey,
            SecurityConstants.REFRESH_TOKEN_TYPE,
            SecurityConstants.REFRESH_TOKEN);
    return prepareRefreshTokenDto(
        userSecurityDetailsDto, tokenMap, SecurityConstants.REFRESH_TOKEN);
  }

  @Override
  public String generatePasswordToken(
      UserSecurityDetailsDto userSecurityDetailsDto, String hashKey) {
    Map<String, Object> tokenMap =
        JwtUtil.generateToken(
            userSecurityDetailsDto,
            hashKey,
            jwtSetPasswordLinkExpirationMs,
            secretKey,
            SecurityConstants.PASSWORD_TOKEN_TYPE,
            SecurityConstants.PASSWORD_TOKEN);
    PasswordTokenDto passwordTokenDto =
        preparePasswordTokenDto(userSecurityDetailsDto, tokenMap, SecurityConstants.PASSWORD_TOKEN);
    userTokenRepository.save(modelMapper.map(passwordTokenDto, UserToken.class));
    UserInfoDto userInfoDto = getUserInfoDto(userSecurityDetailsDto.getUserId());
    if (userInfoDto.getUsername() != null) {
      redisService.setHashValue(
          String.format("%s:%s", userInfoDto.getUsername().toLowerCase(), hashKey),
          hashKey,
          userInfoDto,
          TimeUnit.SECONDS,
          3600L,
          true);
    }
    return passwordTokenDto.getAccessToken();
  }

  /**
   * used to prepare tokenDto from token details and userDto
   *
   * @param userSecurityDetailsDto
   * @param tokenMap
   * @return
   */
  private UserTokenDto prepareTokenDto(
      UserSecurityDetailsDto userSecurityDetailsDto, Map<String, Object> tokenMap, String token) {
    log.info("into prepareTokenDto()");
    UserTokenDto userTokenDto = new UserTokenDto();
    userTokenDto.setAccessToken(tokenMap.get(token).toString());
    userTokenDto.setTokenType(SecurityConstants.TokenType.BEARER);
    userTokenDto.setExpired(false);
    userTokenDto.setCreatedDate((Date) tokenMap.get(SecurityConstants.ISSUE_DATE));
    userTokenDto.setExpiredDate((Date) tokenMap.get(SecurityConstants.EXPIRED_DATE));
    userTokenDto.setUserId(userSecurityDetailsDto.getUserId());
    return userTokenDto;
  }

  private RefreshTokenDto prepareRefreshTokenDto(
      UserSecurityDetailsDto userSecurityDetailsDto, Map<String, Object> tokenMap, String token) {
    log.info("into prepareTokenDto()");
    RefreshTokenDto refreshTokenDto = new RefreshTokenDto();
    refreshTokenDto.setRefreshToken(tokenMap.get(token).toString());
    refreshTokenDto.setTokenType(SecurityConstants.TokenType.BEARER);
    refreshTokenDto.setExpired(false);
    refreshTokenDto.setCreatedDate((Date) tokenMap.get(SecurityConstants.ISSUE_DATE));
    refreshTokenDto.setExpiredDate((Date) tokenMap.get(SecurityConstants.EXPIRED_DATE));
    refreshTokenDto.setUserId(userSecurityDetailsDto.getUserId());
    return refreshTokenDto;
  }

  private PasswordTokenDto preparePasswordTokenDto(
      UserSecurityDetailsDto userSecurityDetailsDto, Map<String, Object> tokenMap, String token) {
    log.info("into preparePasswordTokenDto()");
    PasswordTokenDto passwordTokenDto = new PasswordTokenDto();
    passwordTokenDto.setAccessToken(tokenMap.get(token).toString());
    passwordTokenDto.setTokenType(SecurityConstants.TokenType.BEARER);
    passwordTokenDto.setExpired(false);
    passwordTokenDto.setCreatedDate((Date) tokenMap.get(SecurityConstants.ISSUE_DATE));
    passwordTokenDto.setExpiredDate((Date) tokenMap.get(SecurityConstants.EXPIRED_DATE));
    passwordTokenDto.setUserId(userSecurityDetailsDto.getUserId());
    return passwordTokenDto;
  }

  /**
   * used to extract all the claims from given JWT access token with secret key
   *
   * @param token
   * @return
   */
  @Override
  public Claims extractAllClaims(String token) {
    log.info("into extractAllClaims()");
    return JwtUtil.extractAllClaims(token, secretKey);
  }

  /**
   * used to get session details from given JWT token
   *
   * @param token
   * @return
   */
  @Override
  public Map<String, Object> getUserInfo(String token) {
    log.info("into getSessionUser()");
    Claims claims = getClaims(token);
    Map<String, Object> responseMap = new HashMap<>();
    if (claims != null && claims.get(SecurityConstants.USER_NAME) != null) {
      String username = claims.get(SecurityConstants.USER_NAME).toString();
      String hash = claims.get(SecurityConstants.HASH).toString();
      UserInfoDto userInfoDto;
      userInfoDto =
          (UserInfoDto)
              redisService.getHashValue(
                  String.format("%s:%s", username.toLowerCase(), hash), hash, UserInfoDto.class);
      if (Objects.isNull(userInfoDto)) {
        int userId = Integer.parseInt(claims.get(SecurityConstants.USER_ID).toString());
        userInfoDto = getUserInfoDto(userId);
        Optional<User> user = userRepository.findByUserId(userId);
        if (user.isPresent()) {
          userInfoDto.setLastLoginDate(user.get().getLastLoginDate());
        }
      }
      responseMap.put(SecurityConstants.USER_NAME, username);
      responseMap.put(
          SecurityConstants.ROLES,
          ((ArrayList<String>) claims.get(SecurityConstants.ROLES)).stream().toList());
      responseMap.put(
          SecurityConstants.FUNCTIONS,
          ((ArrayList<String>) claims.get(SecurityConstants.FUNCTIONS))
              .stream().map(auth -> new SimpleGrantedAuthority(auth)).toList());
      responseMap.put(SecurityConstants.USER_INFO_RESULT, userInfoDto);
      responseMap.put(SecurityConstants.HASH, hash);
    }
    return responseMap;
  }

  /**
   * used to parse the given JWT token
   *
   * @param request
   * @return
   */
  @Override
  public String parseToken(HttpServletRequest request) {
    log.info("into parseToken()");
    String authHeader = request.getHeader(SecurityConstants.AUTHORIZATION);
    if (authHeader != null && authHeader.startsWith(SecurityConstants.BEARER_TOKEN)) {
      return authHeader.replace(SecurityConstants.BEARER_TOKEN, "").trim();
    }
    return null;
  }

  /**
   * used to get all the claims from the given JWT token
   *
   * @param token
   * @return
   */
  @Override
  public Claims getClaims(String token) {
    log.info("into getClaims()");
    if (token != null && !token.isEmpty()) {
      return extractAllClaims(token);
    }
    return null;
  }
}
