package io.github.ppzxc.crypto;

public class CryptoRuntimeException extends RuntimeException {

  public CryptoRuntimeException() {
  }

  public CryptoRuntimeException(String message) {
    super(message);
  }

  public CryptoRuntimeException(String message, Throwable cause) {
    super(message, cause);
  }

  public CryptoRuntimeException(Throwable cause) {
    super(cause);
  }

  public CryptoRuntimeException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public static CryptoRuntimeException notSupportedDecrypt() {
    return new CryptoRuntimeException("not supported decrypt");
  }
}
