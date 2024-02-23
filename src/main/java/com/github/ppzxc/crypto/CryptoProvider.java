package com.github.ppzxc.crypto;

public enum CryptoProvider {
  BOUNCY_CASTLE("BC");

  private final String code;

  CryptoProvider(String code) {
    this.code = code;
  }

  public String getCode() {
    return code;
  }
}
