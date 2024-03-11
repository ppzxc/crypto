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

class RsaEncryptorTest {

  private Crypto encryptor;
  private Crypto decryptor;

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa();
    encryptor = CryptoFactory.rsa(keyPair.getPublic());
    decryptor = CryptoFactory.rsa(keyPair);
  }

  @Test
  void should_encrypt_when_byte_array_plain_text() throws CryptoException {
    // given
    byte[] expected = ByteArrayUtils.giveMeOne(128);

    // when
    byte[] cipherText = encryptor.encrypt(expected);
    byte[] actual = decryptor.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  void should_encrypt_when_string_plain_text() throws CryptoException {
    // given
    String expected = RandomUtils.getInstance().string(128);

    // when
    byte[] cipherText = encryptor.encrypt(expected);
    byte[] actual = decryptor.decrypt(cipherText);

    // then
    assertThat(new String(actual, StandardCharsets.UTF_8)).isEqualTo(expected);
  }

  @Test
  void should_encrypt_to_string_when_byte_array() throws CryptoException {
    // given
    byte[] expected = ByteArrayUtils.giveMeOne(128);

    // when
    String cipherText = encryptor.encryptToString(expected);
    byte[] actual = decryptor.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @Test
  void should_encrypt_to_string_when_string() throws CryptoException {
    // given
    String expected = RandomUtils.getInstance().string(128);

    // when
    String cipherText = encryptor.encryptToString(expected);
    byte[] actual = decryptor.decrypt(cipherText);

    // then
    assertThat(new String(actual, StandardCharsets.UTF_8)).isEqualTo(expected);
  }

  @Test
  void should_throw_exception_when_encrypt() {
    assertThatCode(() -> encryptor.encrypt(ByteArrayUtils.giveMeOne())).isInstanceOf(CryptoException.class);
  }

  @Test
  void should_throw_exception_when_decrypt_1() {
    assertThatCode(() -> encryptor.decrypt(new byte[0])).isInstanceOf(CryptoException.class);
  }

  @Test
  void should_throw_exception_when_decrypt_2() {
    assertThatCode(() -> encryptor.decrypt("")).isInstanceOf(CryptoException.class);
  }

  @Test
  void should_throw_exception_when_decrypt_3() {
    assertThatCode(() -> encryptor.decryptToString(new byte[0])).isInstanceOf(CryptoException.class);
  }

  @Test
  void should_throw_exception_when_decrypt_4() {
    assertThatCode(() -> encryptor.decryptToString("")).isInstanceOf(CryptoException.class);
  }

  @Test
  void should_throw_exception_when_builder_1() {
    assertThatCode(() -> RsaEncryptor.builder().transformation(null).build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_builder_2() {
    assertThatCode(() -> RsaEncryptor.builder().cryptoProvider(null).build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_builder_3() {
    assertThatCode(() -> RsaEncryptor.builder().charset(null).build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_builder_4() {
    assertThatCode(() -> RsaEncryptor.builder().publicKey(null).build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_created() {
    assertThatCode(() -> RsaEncryptor.builder()
      .transformation(Transformation.AES_CBC_PKCS5PADDING)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8)
      .publicKey(AsymmetricKeyFactory.generateRsa().getPublic())
      .build())
      .doesNotThrowAnyException();
  }
}