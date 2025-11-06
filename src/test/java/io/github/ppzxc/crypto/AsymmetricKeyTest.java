package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AsymmetricKeyTest {

  @BeforeAll
  static void beforeAll() {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_throw_exception_when_null_type() {
    // given
    AsymmetricKey.Type  type = null;
    String publicKey = StringUtils.giveMeOne();
    String privateKey = StringUtils.giveMeOne();

    // when, then
    assertThatCode(() -> AsymmetricKey.of(type, publicKey, privateKey))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'AsymmetricKey.Type' require not null");
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_null_public_key(String publicKey) {
    // given
    AsymmetricKey.Type type = AsymmetricKey.Type.RSA;
    String privateKey = StringUtils.giveMeOne();

    // when, then
    assertThatCode(() -> AsymmetricKey.of(type, publicKey, privateKey))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'PublicKey' require not blank");
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_null_private_key(String privateKey) {
    // given
    AsymmetricKey.Type type = AsymmetricKey.Type.RSA;
    String publicKey = StringUtils.giveMeOne();

    // when, then
    assertThatCode(() -> AsymmetricKey.of(type, publicKey, privateKey))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'PrivateKey' require not blank");
  }

  private static String[] nullEmptyBlank() {
    return new String[]{null, "", "     "};
  }
}