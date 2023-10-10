package com.optimum.eoms.security.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.optimum.eoms.model.common.dto.UserInfoDto;
import com.optimum.eoms.security.service.RedisService;
import jakarta.transaction.Transactional;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Service;

/** used to provide implementations for redis service methods */
@Slf4j
@Transactional
@Service
public class RedisServiceImpl implements RedisService {

  @Autowired ObjectMapper mapper;

  @Autowired RedisTemplate<String, Object> template;

  /**
   * used to get the session user details from redis cache using hash value
   *
   * @param key
   * @param hashKey
   * @param classValue
   * @return
   */
  @Override
  public synchronized Object getHashValue(
      String key, String hashKey, Class<UserInfoDto> classValue) {
    log.info("into getHashValue() ");
    try {
      template.setHashValueSerializer(new Jackson2JsonRedisSerializer<>(UserInfoDto.class));
      template.setValueSerializer(new Jackson2JsonRedisSerializer<>(UserInfoDto.class));
      Object object = template.opsForHash().get(key, hashKey);
      return mapper.convertValue(object, classValue);
    } catch (RedisConnectionFailureException redisConnectionFailureException) {
      log.info("jedis connection error", redisConnectionFailureException);
      return null;
    }
  }

  /**
   * used to remove the stored hash value from redis cache
   *
   * @param key
   * @param hashKey
   */
  @Override
  public void removeHashValue(String key, String hashKey) {
    log.info("into removeHashValue() ");
    template.opsForHash().delete(key, hashKey);
  }

  /**
   * used to set the hash value in redis cache
   *
   * @param key
   * @param hashKey
   * @param value
   * @param unit
   * @param timeout
   * @param marshal
   */
  @Override
  public void setHashValue(
      String key, String hashKey, Object value, TimeUnit unit, long timeout, boolean marshal) {
    log.info("into setHashValue() ");
    try {
      if (marshal) {
        template.setHashValueSerializer(new Jackson2JsonRedisSerializer<>(UserInfoDto.class));
        template.setValueSerializer(new Jackson2JsonRedisSerializer<>(UserInfoDto.class));
      } else {
        template.setHashValueSerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
      }
      template.opsForHash().put(key, hashKey, value);
      template.expire(key, timeout, unit);
    } catch (RedisConnectionFailureException redisConnectionFailureException) {
      log.info("jedis connection error", redisConnectionFailureException);
    }
  }
}
