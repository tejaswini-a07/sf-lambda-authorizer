package function.service;

import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import function.exception.InvalidInputException;
import function.model.AuthPolicy;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.collections4.MapUtils;

/**
 * Service to generate auth statement response.
 */
public class AuthPolicyService {
  private static final String clientParams = "clientParams";
  private static final TypeReference<Map<String, Object>> typeRef = new TypeReference<>() {
  };
  private static final String regexPattern = "^[/.a-zA-Z0-9-\\*]+$";
  private static final ObjectMapper mapper = new ObjectMapper();
  private static final String  POLICY_VERSION = "2012-10-17";

  /**
   * Method to check authentication and return appropriate policy statement.
   *
   * @param event with auth token and arn.
   * @param logger used to print logs in console.
   * @return a policy statement which describes the allowed methods.
   */
  public Map<String, Object> getAuthPolicy(Map<String, String> event,
                                           LambdaLogger logger, RSAKey publicKey) {

    AuthPolicy policy = new AuthPolicy();
    policy.setPrincipalId("test-Principle"); //ToDo set user Id of client
    policy.setVersion(POLICY_VERSION);
    String[] tmpArn = event.get("methodArn").split(":");
    policy.setAwsAccountId(tmpArn[4]);

    String[] apiGatewayArnTemp = tmpArn[5].split("/");
    policy.setRestApiId(apiGatewayArnTemp[0]);
    policy.setRegion(tmpArn[3]);
    policy.setStage(apiGatewayArnTemp[1]);
    policy.setPathRegex(regexPattern);
    Map<String, Object> claims = new HashMap<>();
    try {
      claims = getClaims(event.get("authorizationToken"), publicKey, logger);
    } catch (ExpiredJwtException ex) {
      logger.log(" JET Token got expired " + ex);
      throw new RuntimeException("Unauthorized");
    }
    if (MapUtils.isNotEmpty(claims)) {
      policy.allowAllMethods();
    } else {
      policy.denyAllMethods();
    }
    try {
      Map<String, Object> authResponse = policy.buildPolicy();
      authResponse.put("context", Collections.singletonMap("claims",
          Base64.getEncoder().encode(
              mapper.writeValueAsString(claims).getBytes(StandardCharsets.UTF_8))));
      return authResponse;
    } catch (JsonProcessingException ex) {
      logger.log("Exception occurred while converting object to string, " + ex);
      throw new InvalidInputException(ex.getMessage());
    }
  }

  /**
   * Extracts claims from jwt token using public key.
   *
   * @param token Jwt token given in input.
   * @param logger logger to print logs in aws console
   * @return returns claims extracted from jwt token.
   */
  public Map<String, Object> getClaims(String token, RSAKey publicKey, LambdaLogger logger) {
    try {
      Claims claims = Jwts.parser().setSigningKey(publicKey.toPublicKey())
          .parseClaimsJws(token).getBody();
      String payload = claims.get(clientParams, String.class);
      logger.log(" payload returned :" + payload);
      return mapper.readValue(payload, typeRef);
    } catch (JOSEException ex) {
      logger.log("The algorithm mentioned was not a valid algorithm to generate publicKey :"
          + ex);
      throw new InvalidInputException(ex.getMessage());
    } catch (JsonProcessingException ex) {
      logger.log("Exception occurred while extracting map object from payload :" + ex);
      throw new InvalidInputException(ex.getMessage());
    }
  }
}
