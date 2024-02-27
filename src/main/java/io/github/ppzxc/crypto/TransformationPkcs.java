package io.github.ppzxc.crypto;

import java.util.Arrays;

/**
 * The enum Transformation pkcs.
 */
public enum TransformationPkcs {
  /**
   * Pkcs 5 padding transformation pkcs.
   */
  PKCS5PADDING("PKCS5Padding"),
  /**
   * Pkcs 7 padding transformation pkcs.
   */
  PKCS7PADDING("PKCS7Padding");

  private final String code;

  TransformationPkcs(String code) {
    this.code = code;
  }

  /**
   * Of transformation pkcs.
   *
   * @param value the value
   * @return the transformation pkcs
   */
  public static TransformationPkcs of(String value) {
    return Arrays.stream(TransformationPkcs.values())
      .filter(type -> type.code.equalsIgnoreCase(value))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(String.format("%s not supported 'AlgorithmPkcs'", value)));
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
