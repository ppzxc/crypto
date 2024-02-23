package com.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class Aes128CbcPkcs7PaddingImplTest {

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 1")
  @Test
  void t0() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    byte[] expected = RandomBytes.giveMeOne();

    // when
    byte[] cipherText = given.encrypt(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 2")
  @Test
  void t1() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    byte[] expected = RandomBytes.giveMeOne();

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 3")
  @Test
  void t2() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    byte[] expected = RandomBytes.giveMeOne();

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(new String(expected, StandardCharsets.UTF_8));
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 4")
  @Test
  void t3() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    byte[] expected = RandomBytes.giveMeOneWithUtf8();

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual.getBytes(StandardCharsets.UTF_8)).isEqualTo(expected);
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 5")
  @Test
  void t4() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    String expected = RandomString.giveMeOne(512);

    // when
    byte[] cipherText = given.encrypt(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 6")
  @Test
  void t5() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    String expected = RandomString.giveMeOne(512);

    // when
    byte[] cipherText = given.encrypt(expected.getBytes(StandardCharsets.UTF_8));
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 7")
  @Test
  void t6() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 8")
  @Test
  void t7() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText.getBytes(StandardCharsets.UTF_8));

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 9")
  @Test
  void t8() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes 128 로 초기화된 crypto 로 암/복호화 할 수 있다. 10")
  @Test
  void t9() throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(16), Transformation.AES_CBC_PKCS7PADDING);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText.getBytes(StandardCharsets.UTF_8));

    // then
    assertThat(actual).isEqualTo(expected);
  }
}