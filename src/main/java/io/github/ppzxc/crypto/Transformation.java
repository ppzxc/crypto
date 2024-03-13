package io.github.ppzxc.crypto;

import static io.github.ppzxc.crypto.TransformationMode.CIPHER_BLOCK_CHAINING;
import static io.github.ppzxc.crypto.TransformationMode.CIPHER_FEEDBACK;
import static io.github.ppzxc.crypto.TransformationMode.COUNTER;
import static io.github.ppzxc.crypto.TransformationMode.ELECTRONIC_CODE_BLOCK;
import static io.github.ppzxc.crypto.TransformationMode.OUTPUT_FEEDBACK;
import static io.github.ppzxc.crypto.TransformationPkcs.PKCS5PADDING;
import static io.github.ppzxc.crypto.TransformationPkcs.PKCS7PADDING;
import static io.github.ppzxc.crypto.TransformationType.ADVANCED_ENCRYPTION_STANDARD;

import java.util.Arrays;

public enum Transformation {
  RSA(TransformationType.RSA, null, null),
  AES_ECB_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, ELECTRONIC_CODE_BLOCK, PKCS5PADDING),
  AES_ECB_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, ELECTRONIC_CODE_BLOCK, PKCS7PADDING),
  AES_CBC_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_BLOCK_CHAINING, PKCS5PADDING),
  AES_CBC_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_BLOCK_CHAINING, PKCS7PADDING),
  AES_CFB_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_FEEDBACK, PKCS5PADDING),
  AES_CFB_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_FEEDBACK, PKCS7PADDING),
  AES_OFB_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, OUTPUT_FEEDBACK, PKCS5PADDING),
  AES_OFB_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, OUTPUT_FEEDBACK, PKCS7PADDING),
  AES_CTR_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, COUNTER, PKCS5PADDING),
  AES_CTR_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, COUNTER, PKCS7PADDING),
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
      return String.format("%s/%s/%s", transformationType.getCode(), transformationMode.getCode(),
        transformationPkcs.getCode());
    }
  }

  public static Transformation of(String type, String mode, String pkcs) {
    return Arrays.stream(Transformation.values())
      .filter(tran -> tran.transformationType.getCode().equalsIgnoreCase(type))
      .filter(tran -> tran.transformationMode.getCode().equalsIgnoreCase(mode))
      .filter(tran -> tran.transformationPkcs.getCode().equalsIgnoreCase(pkcs))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(
        String.format("type=%s mode=%s pkcs=%s not supported transformation", type, mode, pkcs)));
  }

  public TransformationType getTransformationType() {
    return transformationType;
  }

  public TransformationMode getTransformationMode() {
    return transformationMode;
  }

  public TransformationPkcs getTransformationPkcs() {
    return transformationPkcs;
  }
}
