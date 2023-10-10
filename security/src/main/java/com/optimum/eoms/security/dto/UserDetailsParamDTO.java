package com.optimum.eoms.security.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.optimum.eoms.common.constants.AppConstants;
import java.sql.Timestamp;
import java.util.Date;

import com.optimum.eoms.model.common.dto.AuditableDto;
import com.optimum.eoms.model.common.entity.Auditable;
import lombok.Data;

@Data
public class UserDetailsParamDTO extends AuditableDto {
  private int userId;
  private int companyId;
  private String username;
  private String password;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = AppConstants.TIMESTAMP_FORMAT)
  private Date lastLoginDate;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = AppConstants.TIMESTAMP_FORMAT)
  private Timestamp passwordChangeDate;

  private boolean lockedOut;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = AppConstants.TIMESTAMP_FORMAT)
  private Timestamp lockoutDateTime;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = AppConstants.TIMESTAMP_FORMAT)
  private Timestamp userExpiryDate;

  private int failedAttempts;

  private boolean passwordExpired;

}
