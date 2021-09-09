
package function.config;

import redis.clients.jedis.Jedis;

/** Redis configuration. */
public class RedisConfig {

  private static Jedis client;
  private static final String JWKS_HOST = System.getenv("REDISHOST");
  private static final int JWKS_PORT = Integer.parseInt(System.getenv("REDISPORT"));

  /** Get singleton Redis client. */
  public static Jedis getClient() {
    if (client == null) {
      client = new Jedis(JWKS_HOST, JWKS_PORT);
    }
    return client;
  }
}