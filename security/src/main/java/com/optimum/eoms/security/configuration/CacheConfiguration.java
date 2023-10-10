package com.optimum.eoms.security.configuration;

import com.optimum.eoms.security.constants.SecurityConstants;
import java.time.Duration;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/** used to provide required beans for redis cache configuration */
@Configuration
@Slf4j
public class CacheConfiguration {
  @Value("${spring.redis.host}")
  private String redisHost;

  @Value("${spring.redis.port}")
  private Integer redisPort;

  @Value("${spring.redis.password}")
  private String redisPassword;

  @Bean
  JedisConnectionFactory jedisConnectionFactory() {
    log.info("into jedisConnectionFactory()");
    RedisStandaloneConfiguration redisStandaloneConfiguration =
        new RedisStandaloneConfiguration(redisHost, redisPort);
    redisStandaloneConfiguration.setPassword(RedisPassword.of(redisPassword));
    return new JedisConnectionFactory(redisStandaloneConfiguration);
  }

  @Bean
  RedisTemplate<String, Object> redisTemplate() {
    log.info("into redisTemplate()");
    final RedisTemplate<String, Object> template = new RedisTemplate<>();
    template.setConnectionFactory(jedisConnectionFactory());
    template.setKeySerializer(new StringRedisSerializer());

    template.setHashValueSerializer(new Jackson2JsonRedisSerializer<>(Object.class));
    template.setValueSerializer(new Jackson2JsonRedisSerializer<>(Object.class));
    template.setDefaultSerializer(new StringRedisSerializer());
    return template;
  }

  @Bean
  public RedisCacheManager cacheManager(RedisConnectionFactory connectionFactory) {
    RedisCacheConfiguration cacheConfig =
        defaultCacheConfig(Duration.ofMinutes(5)).disableCachingNullValues();

    return RedisCacheManager.builder(jedisConnectionFactory())
        .cacheDefaults(cacheConfig)
        .withCacheConfiguration(
            SecurityConstants.USER_INFO_CACHE, defaultCacheConfig(Duration.ofMinutes(2)))
        .build();
  }

  private RedisCacheConfiguration defaultCacheConfig(Duration duration) {
    return RedisCacheConfiguration.defaultCacheConfig()
        .entryTtl(duration)
        .serializeValuesWith(
            RedisSerializationContext.SerializationPair.fromSerializer(
                new GenericJackson2JsonRedisSerializer()));
  }
}
