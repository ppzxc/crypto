package com.github.ppzxc.crypto;

import java.util.Arrays;

public enum TransformationPkcs {
  PKCS5PADDING("PKCS5Padding"),
  PKCS7PADDING("PKCS7Padding");

  private final String code;

  TransformationPkcs(String code) {
    this.code = code;
  }

  public static TransformationPkcs of(String value) {
    return Arrays.stream(TransformationPkcs.values())
      .filter(type -> type.code.equalsIgnoreCase(value))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(String.format("%s not supported 'AlgorithmPkcs'", value)));
  }

  public String getCode() {
    return code;
  }
}
