package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.StringUtils;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CryptoFactoryTest {

  @BeforeAll
  static void beforeAll() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_throw_exception_invalid_key_size() {
    // given
    byte[] key = StringUtils.giveMeOne(10).getBytes(StandardCharsets.UTF_8);
    TransformationType transformationType = null;
    Transformation transformation = null;
    CryptoProvider cryptoProvider = null;

    // when, then
    assertThatCode(() -> CryptoFactory.aes(key, transformationType, transformation, cryptoProvider,null))
      .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_return_crypto_1() {
    // given
    byte[] key = ByteArrayUtils.giveMeOne(16);
    Transformation transformation = Transformation.AES_CBC_PKCS7PADDING;

    // when, then
    assertThatCode(() -> CryptoFactory.aes(key, transformation)).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_2() {
    // given
    byte[] key = ByteArrayUtils.giveMeOne(16);

    // when, then
    assertThatCode(() -> CryptoFactory.aes(key)).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_3() {
    // given
    String key = StringUtils.giveMeOne(16);

    // when, then
    assertThatCode(() -> CryptoFactory.aes(key)).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_4() {
    assertThatCode(CryptoFactory::aes128).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_5() {
    assertThatCode(CryptoFactory::aes192).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_6() {
    assertThatCode(CryptoFactory::aes256).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_7() {
    assertThatCode(() -> CryptoFactory.rsa(AsymmetricKeyFactory.generateRsa())).doesNotThrowAnyException();
  }
}