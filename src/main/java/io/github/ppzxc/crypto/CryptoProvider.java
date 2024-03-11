package io.github.ppzxc.crypto;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The enum Crypto provider.
 */
public enum CryptoProvider {
  /**
   * Bouncy castle crypto provider.
   */
  NONE("NONE"),
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

  public void addProvider() {
    if (this == CryptoProvider.BOUNCY_CASTLE) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }
}
