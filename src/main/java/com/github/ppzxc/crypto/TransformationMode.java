package com.github.ppzxc.crypto;

import java.util.Arrays;
import lombok.Getter;

@Getter
public enum TransformationMode {
  ELECTRONIC_CODE_BLOCK("ECB"),
  CIPHER_BLOCK_CHAINING("CBC"),
  CIPHER_FEEDBACK("CFB"),
  OUTPUT_FEEDBACK("OFB"),
  COUNTER("CTR");

  private final String code;

  TransformationMode(String code) {
    this.code = code;
  }

  public static TransformationMode of(String value) {
    return Arrays.stream(TransformationMode.values())
      .filter(type -> type.code.equalsIgnoreCase(value))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException("%s not supported 'AlgorithmMode'".formatted(value)));
  }
}
