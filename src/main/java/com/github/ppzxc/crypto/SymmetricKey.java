package com.github.ppzxc.crypto;

public class SymmetricKey {

  private final String key;

  public SymmetricKey(String key) {
    this.key = key;
    if (key == null || key.trim().isEmpty()) {
      throw new IllegalArgumentException("'SymmetricKey' require not blank");
    }
  }

  public String getKey() {
    return key;
  }
}