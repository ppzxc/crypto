package com.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AsymmetricKeyFactoryTest {

  @DisplayName("KeyPair 가 정상 생성 된다.")
  @Test
  void t0() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given

    // when
    KeyPair actual = AsymmetricKeyFactory.generateRsa();

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getPublic()).isNotNull();
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(AsymmetricKeyType.RSA.name());
    assertThat(actual.getPublic().getEncoded()).isNotNull().hasSizeGreaterThan(0);
    assertThat(actual.getPublic().getFormat()).isNotBlank();
    assertThat(actual.getPrivate()).isNotNull();
    assertThat(actual.getPrivate()).isNotNull();
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(AsymmetricKeyType.RSA.name());
    assertThat(actual.getPrivate().getEncoded()).isNotNull().hasSizeGreaterThan(0);
    assertThat(actual.getPrivate().getFormat()).isNotBlank();
  }

  @DisplayName("KeyPair 가 String 으로 정상 변환된다.")
  @Test
  void t1() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair given = AsymmetricKeyFactory.generateRsa();

    // when
    AsymmetricKey actual = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKeyType.RSA, given);

    // then
    assertThat(actual.getPublicKey()).isNotBlank().contains(AsymmetricKeyFactory.DEFAULT_PUBLIC_KEY_COMMENT);
    assertThat(actual.getPrivateKey()).isNotBlank().contains(AsymmetricKeyFactory.DEFAULT_PRIVATE_RSA_KEY_COMMENT);
  }

  @DisplayName("String Key 가 KeyPair 로 정상 변환 된다.")
  @Test
  void t2() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair expected = AsymmetricKeyFactory.generateRsa();
    AsymmetricKey given = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKeyType.RSA, expected);

    // when
    KeyPair actual = AsymmetricKeyFactory.generate(given);

    // then
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(expected.getPublic().getAlgorithm());
    assertThat(actual.getPublic().getFormat()).isEqualTo(expected.getPublic().getFormat());
    assertThat(actual.getPublic().getEncoded()).isEqualTo(expected.getPublic().getEncoded());
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(expected.getPrivate().getAlgorithm());
    assertThat(actual.getPrivate().getFormat()).isEqualTo(expected.getPrivate().getFormat());
    assertThat(actual.getPrivate().getEncoded()).isEqualTo(expected.getPrivate().getEncoded());
  }

  @DisplayName("1024 bit key size Key 가 정상 생성된다")
  @Test
  void t3() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair expected = AsymmetricKeyFactory.generateRsa(1024);
    AsymmetricKey given = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKeyType.RSA, expected);

    // when
    KeyPair actual = AsymmetricKeyFactory.generate(given);

    // then
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(expected.getPublic().getAlgorithm());
    assertThat(actual.getPublic().getFormat()).isEqualTo(expected.getPublic().getFormat());
    assertThat(actual.getPublic().getEncoded()).isEqualTo(expected.getPublic().getEncoded());
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(expected.getPrivate().getAlgorithm());
    assertThat(actual.getPrivate().getFormat()).isEqualTo(expected.getPrivate().getFormat());
    assertThat(actual.getPrivate().getEncoded()).isEqualTo(expected.getPrivate().getEncoded());
  }

  @DisplayName("2048 bit key size Key 가 정상 생성된다")
  @Test
  void t4() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair expected = AsymmetricKeyFactory.generateRsa(2048);
    AsymmetricKey given = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKeyType.RSA, expected);

    // when
    KeyPair actual = AsymmetricKeyFactory.generate(given);

    // then
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(expected.getPublic().getAlgorithm());
    assertThat(actual.getPublic().getFormat()).isEqualTo(expected.getPublic().getFormat());
    assertThat(actual.getPublic().getEncoded()).isEqualTo(expected.getPublic().getEncoded());
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(expected.getPrivate().getAlgorithm());
    assertThat(actual.getPrivate().getFormat()).isEqualTo(expected.getPrivate().getFormat());
    assertThat(actual.getPrivate().getEncoded()).isEqualTo(expected.getPrivate().getEncoded());
  }
}