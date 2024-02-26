package com.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class SymmetricKey {

  public static final Charset CHARSET = StandardCharsets.UTF_8;
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

  public byte[] getKeyByteArray(Charset charset) {
    return key.getBytes(charset);
  }

  public byte[] getKeyByteArray() {
    return getKeyByteArray(CHARSET);
  }
}