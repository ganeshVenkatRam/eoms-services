package com.optimum.eoms.security.util;

import java.util.Date;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/** used to provide user session details to store in redis cache */
@Data
@Slf4j
public class SessionUser {
  private String username;
  private Date created;
}
