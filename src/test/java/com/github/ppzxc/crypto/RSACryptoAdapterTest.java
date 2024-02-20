package com.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class RSACryptoAdapterTest {

  private RSACrypto rsaCrypto;

  @BeforeEach
  void setUp() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    KeyPair keyPair = RSAKeyFactory.generate();
    rsaCrypto = RSACryptoAdapter.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
  }

  @DisplayName("rsa 를 사용해서 암호화 된다.")
  @Test
  void t0() throws CryptoException {
    // given
    byte[] plainText = RandomBytes.giveMeOne(245);

    // when
    byte[] cipherText = rsaCrypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText);
  }

  @DisplayName("rsa 를 사용해서 복호화 된다.")
  @Test
  void t1() throws CryptoException {
    // given
    byte[] expected = RandomBytes.giveMeOne(245);
    byte[] cipherText = rsaCrypto.encrypt(expected);

    // when
    byte[] actual = rsaCrypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }
}