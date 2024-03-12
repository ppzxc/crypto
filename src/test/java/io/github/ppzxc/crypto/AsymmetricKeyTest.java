package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AsymmetricKeyTest {

  @BeforeAll
  static void beforeAll() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_throw_exception_when_null_type() {
    // given
    AsymmetricKeyType asymmetricKeyType = null;
    String publicKey = StringUtils.giveMeOne();
    String privateKey = StringUtils.giveMeOne();

    // when, then
    assertThatCode(() -> AsymmetricKey.of(asymmetricKeyType, publicKey, privateKey))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'AsymmetricKeyType' require not null");
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_null_public_key(String publicKey) {
    // given
    AsymmetricKeyType asymmetricKeyType = AsymmetricKeyType.RSA;
    String privateKey = StringUtils.giveMeOne();

    // when, then
    assertThatCode(() -> AsymmetricKey.of(asymmetricKeyType, publicKey, privateKey))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'PublicKey' require not blank");
  }

  @ParameterizedTest
  @MethodSource("nullEmptyBlank")
  void should_throw_exception_when_null_private_key(String privateKey) {
    // given
    AsymmetricKeyType asymmetricKeyType = AsymmetricKeyType.RSA;
    String publicKey = StringUtils.giveMeOne();

    // when, then
    assertThatCode(() -> AsymmetricKey.of(asymmetricKeyType, publicKey, privateKey))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'PrivateKey' require not blank");
  }

  private static String[] nullEmptyBlank() {
    return new String[]{null, "", "     "};
  }
}