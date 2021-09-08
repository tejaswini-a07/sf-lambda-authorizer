
package function.model;

/**
 * Enum for all the http methods.
 */
public enum HttpMethod {
  GET("GET"), POST("POST"), PUT("PUT"), PATCH("PATCH"),
  HEAD("HEAD"), DELETE("DELETE"), OPTIONS("OPTION"), ALL("*");

  private final String methodName;

  public String getMethodName() {
    return methodName;
  }

  HttpMethod(String methodName) {
    this.methodName = methodName;
  }
}