package com.github.ppzxc.crypto;

import java.util.Arrays;
import lombok.Getter;

@Getter
public enum TransformationType {
  RSA("RSA"),
  DATA_ENCRYPTION_STANDARD("DES"),
  ADVANCED_ENCRYPTION_STANDARD("AES");

  private final String code;

  TransformationType(String code) {
    this.code = code;
  }

  public static TransformationType of(String value) {
    return Arrays.stream(TransformationType.values())
      .filter(type -> type.code.equalsIgnoreCase(value))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException("%s not supported 'AlgorithmType'".formatted(value)));
  }
}
