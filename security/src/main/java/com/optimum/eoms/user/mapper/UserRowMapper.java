package com.optimum.eoms.user.mapper;

import com.optimum.eoms.common.constants.AppConstants;
import com.optimum.eoms.model.user.constants.UserConstants;
import com.optimum.eoms.model.user.dto.UserSearchResultsDto;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.jdbc.core.RowMapper;

public class UserRowMapper implements RowMapper<UserSearchResultsDto> {

  @Override
  public UserSearchResultsDto mapRow(ResultSet rs, int rowNum) throws SQLException {
    UserSearchResultsDto resultsDto = new UserSearchResultsDto();
    resultsDto.setTotalRecords(rs.getInt(AppConstants.TOTAL_RECORDS));
    resultsDto.setUserId(rs.getInt(UserConstants.USER_ID));
    resultsDto.setUsername(rs.getString(UserConstants.USERNAME));
    resultsDto.setFullName(rs.getString(UserConstants.FULL_NAME));
    resultsDto.setPassword(rs.getString(UserConstants.PASSWORD));
    resultsDto.setLastLoginDate(rs.getTimestamp(UserConstants.LAST_LOGIN_DATE));
    resultsDto.setPasswordChangeDate(rs.getTimestamp(UserConstants.PASSWORD_CHANGE_DATE));
    resultsDto.setLockedout(rs.getBoolean(UserConstants.LOCKEDOUT));
    resultsDto.setLockoutDatetime(rs.getTimestamp(UserConstants.LOCKOUT_DATETIME));
    resultsDto.setUserExpiryDate(rs.getTimestamp(UserConstants.USER_EXPIRY_DATE));
    resultsDto.setFailedAttempts(rs.getInt(UserConstants.FAILED_ATTEMPTS));
    resultsDto.setPasswordExpired(rs.getBoolean(UserConstants.PASSWORD_EXPIRED));
    resultsDto.setRemarks(rs.getString(UserConstants.REMARKS));
    resultsDto.setCreatedDate(rs.getTimestamp(UserConstants.CREATED_DATE));
    resultsDto.setCreatedBy(rs.getInt(UserConstants.CREATED_BY));
    resultsDto.setUpdatedDate(rs.getTimestamp(UserConstants.UPDATED_DATE));
    resultsDto.setUpdatedBy(rs.getInt(UserConstants.UPDATED_BY));
    resultsDto.setActive(rs.getBoolean(UserConstants.ISACTIVE));
    resultsDto.setVersion(rs.getInt(UserConstants.VERSION));

    // mapper for join fields
    resultsDto.setCreatedByName(rs.getString(UserConstants.CREATED_BY_NAME));
    resultsDto.setUpdatedByName(rs.getString(UserConstants.UPDATED_BY_NAME));

    return resultsDto;
  }
}
