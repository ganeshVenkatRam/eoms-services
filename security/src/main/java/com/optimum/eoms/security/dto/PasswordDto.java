package com.optimum.eoms.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordDto {

  @NotBlank private String password;

  @NotBlank private String confirmPassword;
}
