package function.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AuthPolicy model.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthPolicy {

  private String awsAccountId;
  private String principalId;
  private String version;
  private String pathRegex;
  private List<Map<String, Object>> allowMethods;
  private List<Map<String, Object>> denyMethods;
  private String restApiId;
  private String region;
  private String stage;
  private Map<String, Object> policyDocument;

  private static final List<String> allowedMethods =
      List.of("GET", "POST", "PUT", "PATCH", "HEAD", "DELETE", "OPTION", "*");

  public void allowAllMethods() {
    this.addMethod("Allow", HttpMethod.ALL.getMethodName(), "*", new ArrayList<>());
  }

  public void denyAllMethods() {
    this.addMethod("Deny", HttpMethod.ALL.getMethodName(), "*", new ArrayList<>());
  }


  private void addMethod(String effect, String method,
                         String resource, List<Map<String, Object>> conditions) {
    if (!allowedMethods.contains(method)) {
      throw new RuntimeException("Invalid HTTP verb "
          + method + ". Allowed verbs in HttpVerb class");
    }
    if (!resource.matches(pathRegex)) {
      throw new RuntimeException("Invalid resource path: "
          + resource + ". Path should match " + pathRegex);
    }

    if (resource.substring(0, 1).equalsIgnoreCase("/")) {
      resource = resource.substring(1);
    }

    String resourceArn = new StringBuilder("arn:aws:execute-api:")
        .append(region).append(":")
        .append(awsAccountId).append(":")
        .append(restApiId).append("/")
        .append(stage).append("/")
        .append(method).append("/")
        .append(resource).toString();


    if (effect.equalsIgnoreCase("allow")) {
      List<Map<String, Object>> allowedMethods = new ArrayList<>();
      Map<String, Object> arnDetails = new HashMap<>();
      arnDetails.put("resourceArn", resourceArn);
      arnDetails.put("conditions", conditions);
      allowedMethods.add(arnDetails);
      this.allowMethods = allowedMethods;
    }

    if (effect.equalsIgnoreCase("deny")) {
      List<Map<String, Object>> deniedMethods = new ArrayList<>();
      Map<String, Object> arnDetails = new HashMap<>();
      arnDetails.put("resourceArn", resourceArn);
      arnDetails.put("conditions", conditions);
      deniedMethods.add(arnDetails);
      this.denyMethods = deniedMethods;
    }
  }

  private Map<String, Object> getEmptyStatement(String effect) {
    Map<String, Object> statement = new HashMap<>();
    statement.put("Action", "execute-api:Invoke");
    statement.put("Effect", effect.substring(0, 1).toUpperCase()
        + effect.substring(1).toLowerCase());
    statement.put("Resource", new ArrayList<>());
    return statement;
  }

  private List<Map<String, Object>> getStatementForEffect(String effect,
                                                          List<Map<String, Object>> methods) {
    List<Map<String, Object>> statements = new ArrayList<>();
    if (methods == null || methods.size() == 0) {
      return statements;
    }
    Map<String, Object> statement = getEmptyStatement(effect);
    for (Map<String, Object> method : methods) {
      if (!method.containsKey("conditions") || ((List) method.get("conditions")).size() == 0) {
        statement.put("Resource", method.get("resourceArn"));
      } else {
        Map<String, Object> conditionalStatement = getEmptyStatement(effect);
        conditionalStatement.put("Resource", method.get("resourceArn"));
        conditionalStatement.put("condition", method.get("conditions"));
        statements.add(conditionalStatement);
      }
    }
    if (statement.containsKey("Resource")) {
      statements.add(statement);
    }
    return statements;
  }

  /**
   * Build response policy document.
   */
  public Map<String, Object> buildPolicy() {
    if ((this.allowMethods == null || this.allowMethods.size() == 0)
        && (this.denyMethods == null || this.denyMethods.size() == 0)) {
      throw new RuntimeException("No statements defined for the policy");
    }
    Map<String, Object> policy = new HashMap<>();
    policy.put("principalId", this.principalId);
    List<Map<String, Object>> allowStatements =
        this.getStatementForEffect("Allow", allowMethods);
    List<Map<String, Object>> denyStatements =
        this.getStatementForEffect("Deny", denyMethods);

    Map<String, Object> policyDocument = new HashMap<>();
    policyDocument.put("Version", this.version);
    List<Map<String, Object>> statements = new ArrayList<>();
    statements.addAll(allowStatements);
    statements.addAll(denyStatements);
    policyDocument.put("Statement", statements);
    policy.put("policyDocument", policyDocument);
    return policy;
  }
}