package io.github.ppzxc.crypto;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public enum CryptoProvider {
  NONE("NONE"),
  BOUNCY_CASTLE("BC");

  private final String code;

  CryptoProvider(String code) {
    this.code = code;
  }

  public String getCode() {
    return code;
  }

  public void addProvider() {
    if (this == CryptoProvider.BOUNCY_CASTLE) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }
}
