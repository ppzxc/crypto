package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class EmptyCryptoTest {

  @Test
  void should_return_empty_when_byte_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.encrypt(RandomBytes.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }

  @Test
  void should_return_empty_when_string_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.encrypt(RandomString.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }

  @Test
  void should_return_null_when_byte_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    String actual = crypto.encryptToString(RandomBytes.giveMeOne());

    // then
    assertThat(actual).isNull();
  }

  @Test
  void should_return_null_when_string_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    String actual = crypto.encryptToString(RandomString.giveMeOne());

    // then
    assertThat(actual).isNull();
  }

  @Test
  void should_return_empty_when_byte_decrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.decrypt(RandomBytes.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }

  @Test
  void should_return_empty_when_string_decrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.decrypt(RandomString.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }
}