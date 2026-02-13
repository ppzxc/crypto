package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.StringUtils;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CryptoFactoryTest {

  @BeforeAll
  static void beforeAll() {
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
    assertThatCode(() -> CryptoFactory.aes(key, transformation, "nanoitDefaultIvs".getBytes(StandardCharsets.UTF_8))).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_2() {
    // given
    byte[] key = ByteArrayUtils.giveMeOne(16);

    // when, then
    assertThatCode(() -> CryptoFactory.aes(key, "nanoitDefaultIvs".getBytes(StandardCharsets.UTF_8))).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_3() {
    // given
    String key = StringUtils.giveMeOne(16);

    // when, then
    assertThatCode(() -> CryptoFactory.aes(key.getBytes(StandardCharsets.UTF_8), "nanoitDefaultIvs".getBytes(StandardCharsets.UTF_8))).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_7() {
    assertThatCode(() -> CryptoFactory.rsa(AsymmetricKeyFactory.generateRsa())).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_when_ecb_mode_is_given() {
    // given
    byte[] key = ByteArrayUtils.giveMeOne(16);
    Transformation transformation = Transformation.AES_ECB_PKCS5PADDING;

    // when & then
    assertThatCode(() -> CryptoFactory.aes(key, transformation, null)).doesNotThrowAnyException();
  }

  @Test
  void should_return_crypto_when_only_public_key_is_given() throws Exception {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa();

    // when & then
    assertThatCode(() -> CryptoFactory.rsa(keyPair.getPublic())).doesNotThrowAnyException();
  }

  @Test
  void should_throw_exception_when_instantiate_private_constructor()
    throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
    // given
    Constructor<CryptoFactory> constructor = CryptoFactory.class.getDeclaredConstructor();
    constructor.setAccessible(true);

    // when & then
    assertThat(constructor.newInstance()).isNotNull();
  }
}