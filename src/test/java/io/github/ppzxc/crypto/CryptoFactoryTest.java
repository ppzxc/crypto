package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.RandomUtils;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CryptoFactoryTest {

  @Test
  void should_throw_exception_invalid_key_size() {
    // given
    assertThatCode(
      () -> CryptoFactory.aes(RandomUtils.getInstance().string(10).getBytes(StandardCharsets.UTF_8), null, null, null,
        null)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void should_return_crypto_1() {
    assertThatCode(() -> CryptoFactory.aes(ByteArrayUtils.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING))
      .doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_2() {
    assertThatCode(() -> CryptoFactory.aes(ByteArrayUtils.giveMeOne(16))).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_3() {
    assertThatCode(() -> CryptoFactory.aes(RandomUtils.getInstance().string(16))).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_4() {
    assertThatCode(() -> CryptoFactory.aes128()).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_5() {
    assertThatCode(() -> CryptoFactory.aes192()).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_6() {
    assertThatCode(() -> CryptoFactory.aes256()).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_7() {
    assertThatCode(() -> CryptoFactory.rsa(AsymmetricKeyFactory.generateRsa())).doesNotThrowAnyException();
  }
}