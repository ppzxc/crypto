package com.github.ppzxc.crypto;

import java.util.Arrays;
import lombok.Getter;

@Getter
public enum Transformation {
  RSA(TransformationType.RSA, null, null),
  AES_CBC_PKCS5PADDING(TransformationType.ADVANCED_ENCRYPTION_STANDARD, TransformationMode.CIPHER_BLOCK_CHAINING,
    TransformationPkcs.PKCS5PADDING),
  AES_CBC_PKCS7PADDING(TransformationType.ADVANCED_ENCRYPTION_STANDARD, TransformationMode.CIPHER_BLOCK_CHAINING,
    TransformationPkcs.PKCS7PADDING),
  ;

  private final TransformationType transformationType;
  private final TransformationMode transformationMode;
  private final TransformationPkcs transformationPkcs;

  Transformation(TransformationType transformationType, TransformationMode transformationMode,
    TransformationPkcs transformationPkcs) {
    this.transformationType = transformationType;
    this.transformationMode = transformationMode;
    this.transformationPkcs = transformationPkcs;
  }

  public String getCode() {
    if (transformationType == TransformationType.RSA) {
      return transformationType.getCode();
    } else {
      return "%s/%s/%s".formatted(transformationType.getCode(), transformationMode.getCode(),
        transformationPkcs.getCode());
    }
  }

  public static Transformation of(String type, String mode, String pkcs) {
    return Arrays.stream(Transformation.values())
      .filter(tran -> tran.transformationType.getCode().equalsIgnoreCase(type))
      .filter(tran -> tran.transformationMode == null || tran.transformationMode.getCode().equalsIgnoreCase(mode))
      .filter(tran -> tran.transformationPkcs == null || tran.transformationPkcs.getCode().equalsIgnoreCase(pkcs))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(
        "type=%s mode=%s pkcs=%s not supported transformation".formatted(type, mode, pkcs)));
  }
}
