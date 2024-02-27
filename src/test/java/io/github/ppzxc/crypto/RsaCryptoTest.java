package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

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
  void should_encryption_when_use_rsa() throws CryptoException {
    // given
    byte[] plainText = RandomBytes.giveMeOne(245);

    // when
    byte[] cipherText = crypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText);
  }

  @Test
  void should_decryption_when_use_rsa() throws CryptoException {
    // given
    byte[] expected = RandomBytes.giveMeOne(245);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }
}