package function;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;
import function.config.RedisConfig;
import function.service.AuthPolicyService;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.json.JSONObject;
import redis.clients.jedis.Jedis;

/**
 * Lambda Authorizer Handler function.
 */
public class LambdaAuthorizer implements RequestHandler<Map<String, String>, Map<String, Object>> {

  private final AuthPolicyService authPolicyService;
  private final Jedis redisClient;
  private final ObjectMapper mapper;
  private static TypeReference<Map<String, String>> typeRef = new TypeReference<>() {
  };

  private static final String publicKeyRedis = "publicKey";
  private static final String publicKeyId = "kid";

  /**
   * Lambda Authorizer constructor.
   */
  public LambdaAuthorizer() {
    redisClient = RedisConfig.getClient();
    authPolicyService = new AuthPolicyService();
    mapper = new ObjectMapper();
  }

  @Override
  public Map<String, Object> handleRequest(Map<String, String> event, Context context) {
    LambdaLogger logger = context.getLogger();

    logger.log(" event payload received :" + event);
    String keyId = getKeyIdFromToken(event.get("authorizationToken"));
    Set<RSAKey> publicKeys = getAllPublicKeys();
    RSAKey publicKey = null;
    for (RSAKey rsaKey1 : publicKeys) {
      if (rsaKey1.getKeyID().equals(keyId)) {
        publicKey = rsaKey1;
      }
    }
    if (publicKey == null) {
      logger.log("No public key found in redis which with private key");
      throw new RuntimeException("Unauthorized");
    }
    return authPolicyService.getAuthPolicy(event, logger,
        publicKey);
  }

  private String getKeyIdFromToken(String token) {
    String[] tokenPayload = token.split("\\.");
    String headersPayload = tokenPayload[0];
    JSONObject decodedString = new JSONObject(
        new String(Base64.getDecoder().decode(headersPayload)));
    return decodedString.get(publicKeyId).toString();
  }

  private Set<RSAKey> getAllPublicKeys() {
    return redisClient.smembers(publicKeyRedis).stream()
        .map(key ->  redisClient.hgetAll(publicKeyRedis + ":" + key))
        .map(
            key -> {
              try {
                return RSAKey.parse(mapper.writeValueAsString(key));
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            })
        .collect(Collectors.toSet());
  }
}