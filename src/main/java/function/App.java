package function;

/**
 * app start point.
 */
public class App {
  public static void main(String[] args) throws Exception {
    LambdaAuthorizer lambda = new LambdaAuthorizer();
    lambda.handleRequest(null, null);
  }
}