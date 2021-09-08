package function.exception;

/**
 * Exception corresponding to invalid input.
 */
public class InvalidInputException extends RuntimeException {

  /**
   * InvalidInputException constructor.
   *
   * @param message error description {@link String}
   */
  public InvalidInputException(String message) {
    super(message);
  }
}