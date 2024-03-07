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

/**
 * The enum Transformation.
 */
public enum Transformation {
  /**
   * Rsa transformation.
   */
  RSA(TransformationType.RSA, null, null),
  /**
   * Aes ecb pkcs 5 padding transformation.
   */
  AES_ECB_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, ELECTRONIC_CODE_BLOCK, PKCS5PADDING),
  /**
   * Aes ecb pkcs 7 padding transformation.
   */
  AES_ECB_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, ELECTRONIC_CODE_BLOCK, PKCS7PADDING),
  /**
   * Aes cbc pkcs 5 padding transformation.
   */
  AES_CBC_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_BLOCK_CHAINING, PKCS5PADDING),
  /**
   * Aes cbc pkcs 7 padding transformation.
   */
  AES_CBC_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_BLOCK_CHAINING, PKCS7PADDING),
  /**
   * Aes cfb pkcs 5 padding transformation.
   */
  AES_CFB_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_FEEDBACK, PKCS5PADDING),
  /**
   * Aes cfb pkcs 7 padding transformation.
   */
  AES_CFB_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, CIPHER_FEEDBACK, PKCS7PADDING),
  /**
   * Aes ofb pkcs 5 padding transformation.
   */
  AES_OFB_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, OUTPUT_FEEDBACK, PKCS5PADDING),
  /**
   * Aes ofb pkcs 7 padding transformation.
   */
  AES_OFB_PKCS7PADDING(ADVANCED_ENCRYPTION_STANDARD, OUTPUT_FEEDBACK, PKCS7PADDING),
  /**
   * Aes ctr pkcs 5 padding transformation.
   */
  AES_CTR_PKCS5PADDING(ADVANCED_ENCRYPTION_STANDARD, COUNTER, PKCS5PADDING),
  /**
   * Aes ctr pkcs 7 padding transformation.
   */
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

  /**
   * Gets code.
   *
   * @return the code
   */
  public String getCode() {
    if (transformationType == TransformationType.RSA) {
      return transformationType.getCode();
    } else {
      return String.format("%s/%s/%s", transformationType.getCode(), transformationMode.getCode(),
        transformationPkcs.getCode());
    }
  }

  /**
   * Of transformation.
   *
   * @param type the type
   * @param mode the mode
   * @param pkcs the pkcs
   * @return the transformation
   */
  public static Transformation of(String type, String mode, String pkcs) {
    return Arrays.stream(Transformation.values())
      .filter(tran -> tran.transformationType.getCode().equalsIgnoreCase(type))
      .filter(tran -> tran.transformationMode.getCode().equalsIgnoreCase(mode))
      .filter(tran -> tran.transformationPkcs.getCode().equalsIgnoreCase(pkcs))
      .findAny()
      .orElseThrow(() -> new IllegalArgumentException(
        String.format("type=%s mode=%s pkcs=%s not supported transformation", type, mode, pkcs)));
  }

  /**
   * Gets transformation type.
   *
   * @return the transformation type
   */
  public TransformationType getTransformationType() {
    return transformationType;
  }

  /**
   * Gets transformation mode.
   *
   * @return the transformation mode
   */
  public TransformationMode getTransformationMode() {
    return transformationMode;
  }

  /**
   * Gets transformation pkcs.
   *
   * @return the transformation pkcs
   */
  public TransformationPkcs getTransformationPkcs() {
    return transformationPkcs;
  }
}
