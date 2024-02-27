package io.github.ppzxc.crypto;

/**
 * The enum Crypto provider.
 */
public enum CryptoProvider {
  /**
   * Bouncy castle crypto provider.
   */
  BOUNCY_CASTLE("BC");

  private final String code;

  CryptoProvider(String code) {
    this.code = code;
  }

  /**
   * Gets code.
   *
   * @return the code
   */
  public String getCode() {
    return code;
  }
}
