package com.optimum.eoms.security.util;

import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.security.constants.SecurityConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/** used to provide common JWT implementations */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtUtil {

  /**
   * used to generate JWT token for the authenticated user
   *
   * @param userSecurityDetailsDto
   * @param hashKey
   * @param jwtTokenExpirationTime
   * @param secretKey
   */
  public static Map<String, Object> generateToken(
      UserSecurityDetailsDto userSecurityDetailsDto,
      String hashKey,
      long jwtTokenExpirationTime,
      String secretKey,
      String tokenType,
      String token) {
    log.info("into generateRefreshToken() ");
    Map<String, Object> tokenMap = new HashMap<>();
    Date issueDate = new Date(System.currentTimeMillis());
    Date expiredDate = new Date(System.currentTimeMillis() + jwtTokenExpirationTime);
    tokenMap.put(SecurityConstants.ISSUE_DATE, issueDate);
    tokenMap.put(SecurityConstants.EXPIRED_DATE, expiredDate);
    String authToken =
        Jwts.builder()
            .setHeader((Map<String, Object>) Jwts.header().setType(tokenType))
            .claim(SecurityConstants.USER_NAME, userSecurityDetailsDto.getUsername())
            .claim(SecurityConstants.USER_ID, userSecurityDetailsDto.getUserId())
            .claim(
                SecurityConstants.ROLES,
                userSecurityDetailsDto.getRoleDtoList().stream()
                    .map(role -> role.getRoleName())
                    .toList())
            .claim(
                SecurityConstants.FUNCTIONS,
                userSecurityDetailsDto.getAuthorities().stream()
                    .map(auth -> auth.getAuthority())
                    .toList())
            .claim(SecurityConstants.HASH, hashKey)
            .setIssuedAt(issueDate)
            .setExpiration(expiredDate)
            .signWith(getSignInKey(secretKey), SignatureAlgorithm.HS256)
            .compact();
    tokenMap.put(token, authToken);
    return tokenMap;
  }

  public static Map<String, Object> generatePasswordToken(
      UserSecurityDetailsDto userSecurityDetailsDto,
      String hashKey,
      long jwtTokenExpirationTime,
      String secretKey,
      String tokenType,
      String token) {
    log.info("into generatePasswordToken() ");
    Map<String, Object> tokenMap = new HashMap<>();
    Date issueDate = new Date(System.currentTimeMillis());
    Date expiredDate = new Date(System.currentTimeMillis() + jwtTokenExpirationTime);
    tokenMap.put(SecurityConstants.ISSUE_DATE, issueDate);
    tokenMap.put(SecurityConstants.EXPIRED_DATE, expiredDate);
    String passwordToken =
        Jwts.builder()
            .setHeader(
                (Map<String, Object>) Jwts.header().setType(SecurityConstants.PASSWORD_TOKEN_TYPE))
            .claim(SecurityConstants.USER_NAME, userSecurityDetailsDto.getUsername())
            .claim(SecurityConstants.USER_ID, userSecurityDetailsDto.getUserId())
            .setIssuedAt(issueDate)
            .setExpiration(expiredDate)
            .signWith(getSignInKey(secretKey), SignatureAlgorithm.HS256)
            .compact();
    tokenMap.put(token, passwordToken);
    return tokenMap;
  }

  /**
   * used to extract all claims from the given JWT access token
   *
   * @param token
   * @param secretKey
   * @return
   */
  public static Claims extractAllClaims(String token, String secretKey) {
    log.info("into extractAllClaims() ");
    return Jwts.parserBuilder()
        .setSigningKey(getSignInKey(secretKey))
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  /**
   * used to signin with secret key
   *
   * @param secretKey
   * @return
   */
  public static Key getSignInKey(String secretKey) {
    log.info("into getSignInKey() ");
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
