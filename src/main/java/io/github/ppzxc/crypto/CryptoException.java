package io.github.ppzxc.crypto;

/**
 * The type Crypto exception.
 */
public class CryptoException extends Exception {

  /**
   * Instantiates a new Crypto exception.
   */
  public CryptoException() {
  }

  /**
   * Instantiates a new Crypto exception.
   *
   * @param message the message
   */
  public CryptoException(String message) {
    super(message);
  }

  /**
   * Instantiates a new Crypto exception.
   *
   * @param message the message
   * @param cause   the cause
   */
  public CryptoException(String message, Throwable cause) {
    super(message, cause);
  }

  /**
   * Instantiates a new Crypto exception.
   *
   * @param cause the cause
   */
  public CryptoException(Throwable cause) {
    super(cause);
  }

  /**
   * Instantiates a new Crypto exception.
   *
   * @param message            the message
   * @param cause              the cause
   * @param enableSuppression  the enable suppression
   * @param writableStackTrace the writable stack trace
   */
  public CryptoException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public static CryptoException notSupportedDecrypt() {
    return new CryptoException("not supported decrypt");
  }
}
