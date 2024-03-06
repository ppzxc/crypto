package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.RandomUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AsymmetricKeyTest {

  @Test
  void should_throw_exception_when_null_type() {
    assertThatCode(() -> AsymmetricKey.of(null, RandomUtils.getInstance().string(), RandomUtils.getInstance().string()))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'AsymmetricKeyType' require not null");
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_null_public_key(String value) {
    assertThatCode(() -> AsymmetricKey.of(AsymmetricKeyType.RSA, value, RandomUtils.getInstance().string()))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'PublicKey' require not blank");
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_null_private_key(String value) {
    assertThatCode(() -> AsymmetricKey.of(AsymmetricKeyType.RSA, RandomUtils.getInstance().string(), value))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'PrivateKey' require not blank");
  }

  private static String[] nullEmptyBlank() {
    return new String[]{null, "", "     "};
  }
}