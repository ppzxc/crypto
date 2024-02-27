package io.github.ppzxc.crypto;

import java.util.Arrays;

/**
 * The enum Transformation type.
 */
public enum TransformationType {
  /**
   * Rsa transformation type.
   */
  RSA("RSA"),
  /**
   * Data encryption standard transformation type.
   */
  DATA_ENCRYPTION_STANDARD("DES"),
  /**
   * Advanced encryption standard transformation type.
   */
  ADVANCED_ENCRYPTION_STANDARD("AES");

  private final String code;

  TransformationType(String code) {
    this.code = code;
  }

  /**
   * Of transformation type.
   *
   * @param value the value
   * @return the transformation type
   */
  public static TransformationType of(String value) {
    return Arrays.stream(TransformationType.values())
      .filter(type -> type.code.equalsIgnoreCase(value))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(String.format("%s not supported 'AlgorithmType'", value)));
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
