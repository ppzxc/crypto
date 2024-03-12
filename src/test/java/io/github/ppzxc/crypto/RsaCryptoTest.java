package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.crypto.RsaCrypto.Builder;
import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.StringUtils;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RsaCryptoTest {

  private Crypto crypto;

  @BeforeAll
  static void beforeAll() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa();
    crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
  }

  @Test
  void should_throw_exception_when_invalid_byte_array() {
    // given
    byte[] plainText = null;

    // when, then
    assertThatCode(() -> crypto.encrypt(plainText)).isInstanceOf(CryptoException.class);
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
    String plainText = StringUtils.giveMeOne(256);

    // when
    byte[] cipherText = crypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void should_throw_exception_when_invalid_cipher_text() {
    assertThatCode(() -> crypto.decrypt(ByteArrayUtils.giveMeOne(1))).isInstanceOf(CryptoException.class);
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
    String expected = StringUtils.giveMeOne(256);
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
    String expected = StringUtils.giveMeOne(256);
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
    // given
    Builder given = RsaCrypto.builder();

    // when, then
    assertThatCode(() -> given.transformation(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_null_provider() {
    // given
    Builder given = RsaCrypto.builder();
    given.transformation(Transformation.RSA);

    // when, then
    assertThatCode(() -> given.cryptoProvider(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_provider() {
    // given
    Builder given = RsaCrypto.builder();
    given.transformation(Transformation.RSA);
    given.cryptoProvider(CryptoProvider.BOUNCY_CASTLE);

    // when, then
    assertThatCode(given::build).doesNotThrowAnyException();
  }

  @Test
  void should_throw_exception_when_null_charset() {
    // given
    Builder given = RsaCrypto.builder();
    given.transformation(Transformation.RSA);
    given.cryptoProvider(CryptoProvider.BOUNCY_CASTLE);

    // when, then
    assertThatCode(() -> given.charset(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_provider_2() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8)
      .build()).doesNotThrowAnyException();
  }

  @Test
  void should_throw_exception_when_not_null_public_key() {
    // given
    Builder given = RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8);

    // when, then
    assertThatCode(() -> given.publicKey(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_private_key() {
    // given
    Builder given = RsaCrypto.builder()
      .transformation(Transformation.RSA)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8);

    // when, then
    assertThatCode(() -> given.privateKey(null)).isInstanceOf(NullPointerException.class);
  }
}