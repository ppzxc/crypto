package io.github.ppzxc.crypto;

import java.util.Arrays;

public enum TransformationType {
  RON_ADI_LEONARD("RSA"),
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
      .orElseThrow(() -> new IllegalArgumentException(String.format("%s not supported 'AlgorithmType'", value)));
  }

  public String getCode() {
    return code;
  }
}
