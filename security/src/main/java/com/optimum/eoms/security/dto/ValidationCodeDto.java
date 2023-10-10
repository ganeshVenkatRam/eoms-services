package com.optimum.eoms.security.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ValidationCodeDto {
    private String username;
    private Integer authCode;
}
