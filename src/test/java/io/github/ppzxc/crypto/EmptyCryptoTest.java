package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.StringUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class EmptyCryptoTest {

  @BeforeAll
  static void beforeAll() {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_return_empty_when_byte_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.encrypt(ByteArrayUtils.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }

  @Test
  void should_return_empty_when_string_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.encrypt(StringUtils.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }

  @Test
  void should_return_null_when_byte_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    String actual = crypto.encryptToString(ByteArrayUtils.giveMeOne());

    // then
    assertThat(actual).isNull();
  }

  @Test
  void should_return_null_when_string_encrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    String actual = crypto.encryptToString(StringUtils.giveMeOne());

    // then
    assertThat(actual).isNull();
  }

  @Test
  void should_return_empty_when_byte_decrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.decrypt(ByteArrayUtils.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }

  @Test
  void should_return_empty_when_string_decrypt() throws CryptoException {
    // given
    Crypto crypto = EmptyCrypto.create();

    // when
    byte[] actual = crypto.decrypt(StringUtils.giveMeOne());

    // then
    assertThat(actual).isEmpty();
  }
}