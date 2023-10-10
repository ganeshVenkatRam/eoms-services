package com.optimum.eoms.security.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.optimum.eoms.security.constants.SecurityConstants.TokenType;
import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenDto {

  private int id;
  private String refreshToken;
  private TokenType tokenType;
  private boolean revoked;
  private boolean expired;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss:SSS")
  private Date createdDate;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss:SSS")
  private Date expiredDate;

  private int userId;
}
