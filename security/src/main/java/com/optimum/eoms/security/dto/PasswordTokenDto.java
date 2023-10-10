package com.optimum.eoms.security.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.optimum.eoms.security.constants.SecurityConstants;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PasswordTokenDto {
    private int id;
    private String accessToken;
    private SecurityConstants.TokenType tokenType;
    private boolean revoked;
    private boolean expired;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss:SSS")
    private Date createdDate;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss:SSS")
    private Date expiredDate;

    private int userId;
}
