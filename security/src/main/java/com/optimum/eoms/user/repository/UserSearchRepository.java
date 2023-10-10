package com.optimum.eoms.user.repository;

import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.model.user.dto.UserSearchParamDto;
import com.optimum.eoms.model.user.dto.UserSearchResultsDto;
import java.util.List;

public interface UserSearchRepository {
  List<UserSearchResultsDto> search(UserInfoDto userInfo, UserSearchParamDto searchParamDto);
}
