package com.optimum.eoms.security.service;

import com.optimum.eoms.model.common.dto.UserInfoDto;
import java.util.concurrent.TimeUnit;

/** used to declare required methods for redis service */
public interface RedisService {

  Object getHashValue(final String key, final String hashKey, Class<UserInfoDto> classValue);

  void removeHashValue(final String key, final String hashKey);

  void setHashValue(
      final String key,
      final String hashKey,
      final Object value,
      TimeUnit unit,
      long timeout,
      boolean marshal);
}
