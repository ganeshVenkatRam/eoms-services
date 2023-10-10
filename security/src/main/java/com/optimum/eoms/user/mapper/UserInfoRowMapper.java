package com.optimum.eoms.user.mapper;

import com.optimum.eoms.common.constants.AppConstants;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.employee.constants.EmployeeConstants;
import com.optimum.eoms.model.user.constants.UserConstants;
import java.sql.ResultSet;
import java.sql.SQLException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.RowMapper;

@Slf4j
public class UserInfoRowMapper implements RowMapper<UserInfoDto> {

  @Override
  public UserInfoDto mapRow(ResultSet rs, int rowNum) throws SQLException {
    log.info("into mapRow() ");
    UserInfoDto userInfoDto = new UserInfoDto();
    userInfoDto.setCompanyId(rs.getInt(AppConstants.COMPANY_ID));
    userInfoDto.setUserId(rs.getInt(UserConstants.USER_ID));
    userInfoDto.setUsername(rs.getString(UserConstants.USERNAME));
    userInfoDto.setTitleName(rs.getString(EmployeeConstants.TITLE_NAME));
    userInfoDto.setFullName(rs.getString(EmployeeConstants.FULL_NAME));
    userInfoDto.setDesignationId(rs.getInt(EmployeeConstants.DESIGNATION_ID));
    userInfoDto.setLastLoginDate(rs.getTimestamp(UserConstants.LAST_LOGIN_DATE));
    return userInfoDto;
  }
}
