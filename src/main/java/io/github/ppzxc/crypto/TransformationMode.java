package io.github.ppzxc.crypto;

import java.util.Arrays;

/**
 * The enum Transformation mode.
 */
public enum TransformationMode {
  /**
   * Electronic code block transformation mode.
   */
  ELECTRONIC_CODE_BLOCK("ECB"),
  /**
   * Cipher block chaining transformation mode.
   */
  CIPHER_BLOCK_CHAINING("CBC"),
  /**
   * Cipher feedback transformation mode.
   */
  CIPHER_FEEDBACK("CFB"),
  /**
   * Output feedback transformation mode.
   */
  OUTPUT_FEEDBACK("OFB"),
  /**
   * Counter transformation mode.
   */
  COUNTER("CTR");

  private final String code;

  TransformationMode(String code) {
    this.code = code;
  }

  /**
   * Of transformation mode.
   *
   * @param value the value
   * @return the transformation mode
   */
  public static TransformationMode of(String value) {
    return Arrays.stream(TransformationMode.values())
      .filter(type -> type.code.equalsIgnoreCase(value))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(String.format("%s not supported 'AlgorithmMode'", value)));
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
