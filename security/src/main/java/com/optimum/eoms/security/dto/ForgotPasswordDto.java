package com.optimum.eoms.security.dto;


import com.fasterxml.jackson.annotation.JsonFormat;
import com.optimum.eoms.common.constants.AppConstants;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ForgotPasswordDto {
    private String username;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = AppConstants.DATE_FORMAT)
    private Date dob;
}
