package com.optimum.eoms.user.repository.impl;

import com.optimum.eoms.common.constants.AppConstants;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.user.dto.UserSearchParamDto;
import com.optimum.eoms.model.user.dto.UserSearchResultsDto;
import com.optimum.eoms.user.mapper.UserRowMapper;
import com.optimum.eoms.user.repository.UserSearchRepository;
import io.micrometer.common.util.StringUtils;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
@Transactional(readOnly = true)
@Slf4j
public class UserSearchRepositoryImpl implements UserSearchRepository {
  static final Map<String, String> sortColumnMap = new HashMap<>();

  static {
    sortColumnMap.put("username", "us.username");
    sortColumnMap.put("lastLoginDate", "us.last_login_date");
  }

  @Autowired JdbcTemplate jdbcTemplate;

  @Override
  public List<UserSearchResultsDto> search(
      UserInfoDto userInfo, UserSearchParamDto searchParamDto) {
    StringBuilder searchSql = new StringBuilder();
    List<Object> parameters = new ArrayList<>();
    searchSql
        .append("select")
        .append(" us.user_id,")
        .append(" us.company_id,")
        .append(" us.username,")
        .append(" eob.full_name,")
        .append(" us.password,")
        .append(" us.last_login_date,")
        .append(" us.password_changed_date,")
        .append(" us.lockedout,")
        .append(" us.lockout_datetime,")
        .append(" us.user_expiry_date,")
        .append(" us.failed_attempts,")
        .append(" us.password_expired,")
        .append(" us.remarks,")
        .append(" us.created_date,")
        .append(" us.created_by,")
        .append(" us.updated_date,")
        .append(" us.updated_by,")
        .append(" us.isactive,")
        .append(" us.version,")
        .append(" concat(emp_c.emp_code, ' - ', emp_c.full_name) as created_by_name,")
        .append(" concat(emp_u.emp_code, ' - ', emp_u.full_name) as updated_by_name,")
        .append(" count(1) over() as total_records")
        .append(" FROM")
        .append(" sc_eoms.user us")
        .append(" inner join sc_eoms.emp_onboarding emp_c on(us.created_by = emp_c.emp_id)")
        .append(" left join sc_eoms.emp_onboarding emp_u on(us.updated_by = emp_u.emp_id)")
        .append(" inner join sc_eoms.emp_onboarding eob on(us.user_id = eob.emp_id)")
        .append(" where")
        .append(" us.company_id = ? ");
    // add default company condition
    parameters.add(userInfo.getCompanyId());

    if (StringUtils.isNotEmpty(searchParamDto.getUsername())) {
      parameters.add(searchParamDto.getUsername());
      searchSql.append(" and upper(us.username) = upper(?) ");
    }

    searchSql.append(" and us.isactive = ? ");
    parameters.add(searchParamDto.isActive());

    String sortOrder =
        searchParamDto.getSortOrder() == null
            ? AppConstants.SORT_ORDER_ASC
            : searchParamDto.getSortOrder();

    String sortColumn = searchParamDto.getSortColumn();
    if (StringUtils.isEmpty(sortColumn)) {
      sortColumn = " us.username";
    } else {
      sortColumn = sortColumnMap.get(sortColumn);
      if (sortColumn == null) {
        throw new RuntimeException(
            AppConstants.INVALID_SORT_COLUMN + searchParamDto.getSortColumn());
      }
    }
    String orderBy = " order by " + sortColumn + " " + sortOrder;
    searchSql.append(orderBy);

    int pageNumber = searchParamDto.getPageNumber() == null ? 1 : searchParamDto.getPageNumber();
    int pageSize =
        searchParamDto.getPageSize() == null
            ? AppConstants.DEFAULT_PAGE_SIZE
            : searchParamDto.getPageSize();

    int offset = (pageNumber - 1) * pageSize;
    searchSql.append(" offset ").append(offset).append(" limit ").append(pageSize);
    log.info("PARAMS : {}", parameters);
    log.info("SQL : {}", searchSql);

    return jdbcTemplate.query(
        searchSql.toString(),
        new UserRowMapper(),
        parameters.toArray(new Object[parameters.size()]));
  }
}
