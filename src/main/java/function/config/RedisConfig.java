package function.config;

import redis.clients.jedis.Jedis;

/** Redis configuration. */
public class RedisConfig {

  private static Jedis client;
  private static final String JWKS_HOST = "redisjwkstest.h8c63l.ng.0001.use2.cache.amazonaws.com";
  private static final int JWKS_PORT = 6379;

  /** Get singleton Redis client. */
  public static Jedis getClient() {
    if (client == null) {
      client = new Jedis(JWKS_HOST, JWKS_PORT);
    }
    return client;
  }
}
