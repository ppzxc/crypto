package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class TransformationEnumTest {

  @Test
  void should_return_TransformationType_when_valid_code_is_given() {
    // given
    String code = "AES";

    // when
    TransformationType actual = TransformationType.of(code);

    // then
    assertThat(actual).isEqualTo(TransformationType.ADVANCED_ENCRYPTION_STANDARD);
    assertThat(actual.getCode()).isEqualTo(code);
  }

  @Test
  void should_throw_exception_when_invalid_TransformationType_code_is_given() {
    // given
    String invalidCode = "INVALID";

    // when & then
    assertThatThrownBy(() -> TransformationType.of(invalidCode))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageContaining("not supported 'AlgorithmType'");
  }

  @Test
  void should_return_TransformationMode_when_valid_code_is_given() {
    // given
    String code = "CBC";

    // when
    TransformationMode actual = TransformationMode.of(code);

    // then
    assertThat(actual).isEqualTo(TransformationMode.CIPHER_BLOCK_CHAINING);
    assertThat(actual.getCode()).isEqualTo(code);
  }

  @Test
  void should_throw_exception_when_invalid_TransformationMode_code_is_given() {
    // given
    String invalidCode = "INVALID";

    // when & then
    assertThatThrownBy(() -> TransformationMode.of(invalidCode))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageContaining("not supported 'AlgorithmMode'");
  }

  @Test
  void should_return_TransformationPkcs_when_valid_code_is_given() {
    // given
    String code = "PKCS7Padding";

    // when
    TransformationPkcs actual = TransformationPkcs.of(code);

    // then
    assertThat(actual).isEqualTo(TransformationPkcs.PKCS7PADDING);
    assertThat(actual.getCode()).isEqualTo(code);
  }

  @Test
  void should_throw_exception_when_invalid_TransformationPkcs_code_is_given() {
    // given
    String invalidCode = "INVALID";

    // when & then
    assertThatThrownBy(() -> TransformationPkcs.of(invalidCode))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageContaining("not supported 'AlgorithmPkcs'");
  }
}
