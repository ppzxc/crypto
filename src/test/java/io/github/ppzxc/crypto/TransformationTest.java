package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class TransformationTest {

  @BeforeAll
  static void beforeAll() {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_not_contains_type(String value) {
    assertThatCode(
      () -> Transformation.of(value, "CBC", "PKCS7Padding"))
      .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_not_contains_mode(String value) {
    assertThatCode(
      () -> Transformation.of("AES", value, "PKCS7Padding"))
      .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_not_contains_pkcs(String value) {
    assertThatCode(
      () -> Transformation.of("AES", "CBC", value))
      .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_return_default_1() {
    Transformation given = Transformation.of("AES", "CBC", "PKCS7Padding");
    assertThat(given.getCode()).isEqualTo(Transformation.AES_CBC_PKCS7PADDING.getCode());
  }

  @Test
  void should_return_default_2() {
    assertThatCode(() -> Transformation.of("AES", null, null))
      .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_return_default_3() {
    assertThatCode(() -> Transformation.of("AES", "CBC", null))
      .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_return_transformation_aes_type() {
    assertThat(Transformation.of("AES", "CBC", "PKCS7Padding").getTransformationType())
      .isEqualTo(TransformationType.ADVANCED_ENCRYPTION_STANDARD);
  }

  @Test
  void should_return_transformation_cbc_mode() {
    assertThat(Transformation.of("AES", "CBC", "PKCS7Padding").getTransformationMode())
      .isEqualTo(TransformationMode.CIPHER_BLOCK_CHAINING);
  }

  @Test
  void should_return_transformation_pkcs_mode() {
    assertThat(Transformation.of("AES", "CBC", "PKCS7Padding").getTransformationPkcs())
      .isEqualTo(TransformationPkcs.PKCS7PADDING);
  }

  @Test
  void should_throw_exception_when_unsupported_combination() {
    // RSA with PKCS7Padding is not in the enum
    assertThatCode(() -> Transformation.of("RSA", "CBC", "PKCS7Padding"))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageContaining("not supported transformation");
  }

  private static String[] nullEmptyBlank() {
    return new String[]{null, "", "        "};
  }
}