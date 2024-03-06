package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.RandomUtils;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RsaCryptoTest {

  private Crypto crypto;

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa();
    crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
  }

  @Test
  void should_encrypt_byte_array_to_byte_array() throws CryptoException {
    // given
    byte[] plainText = ByteArrayUtils.giveMeOne(245);

    // when
    byte[] cipherText = crypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText);
  }

  @Test
  void should_encrypt_string_to_byte_array() throws CryptoException {
    // given
    String plainText = RandomUtils.getInstance().string(256);

    // when
    byte[] cipherText = crypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void should_decrypt_byte_array_to_byte_array() throws CryptoException {
    // given
    byte[] expected = ByteArrayUtils.giveMeOne(245);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  void should_decrypt_string_to_byte_array() throws CryptoException {
    // given
    String expected = RandomUtils.getInstance().string(256);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void should_encrypt_byte_array_to_string() throws CryptoException {
    // given
    byte[] expected = ByteArrayUtils.giveMeOne(245);
    String cipherText = crypto.encryptToString(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  void should_encrypt_string_to_string() throws CryptoException {
    // given
    String expected = RandomUtils.getInstance().string(256);
    String cipherText = crypto.encryptToString(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void should_decrypt_byte_array_to_string() throws CryptoException {
    // given
    byte[] expected = ByteArrayUtils.giveMeOne(245);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    String actual = crypto.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(new String(expected, StandardCharsets.UTF_8));
  }

  @Test
  void should_throw_exception_when_null_transformation() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(null)
      .build())
      .isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_null_provider() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(null)
      .build())
      .isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_provider() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .build())
      .doesNotThrowAnyException();
  }

  @Test
  void should_throw_exception_when_null_charset() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(null)
      .build())
      .isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_provider_2() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8)
      .build())
      .doesNotThrowAnyException();
  }
}