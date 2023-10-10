package com.optimum.eoms.security.service;

import com.optimum.eoms.model.common.dto.UserSecurityDetailsDto;
import com.optimum.eoms.security.dto.RefreshTokenDto;
import com.optimum.eoms.security.dto.UserTokenDto;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

/** used to declare required methods for JWT service */
public interface JwtService {

  UserTokenDto generateAccessToken(UserSecurityDetailsDto userSecurityDetailsDto, String hashKey);

  RefreshTokenDto generateRefreshToken(
      UserSecurityDetailsDto userSecurityDetailsDto, String hashKey);

  Claims extractAllClaims(String token);

  Map<String, Object> getUserInfo(String token);

  String parseToken(HttpServletRequest request);

  Claims getClaims(String token);

  String generatePasswordToken(UserSecurityDetailsDto userSecurityDetailsDto, String hashKey);
}
