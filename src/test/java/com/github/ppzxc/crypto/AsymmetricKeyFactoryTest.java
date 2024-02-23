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
    KeyPair actual = RsaKeyFactory.generate();

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getPublic()).isNotNull();
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(RsaKeyFactory.TRANSFORMATION.getCode());
    assertThat(actual.getPublic().getEncoded()).isNotNull().hasSizeGreaterThan(0);
    assertThat(actual.getPublic().getFormat()).isNotBlank();
    assertThat(actual.getPrivate()).isNotNull();
    assertThat(actual.getPrivate()).isNotNull();
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(RsaKeyFactory.TRANSFORMATION.getCode());
    assertThat(actual.getPrivate().getEncoded()).isNotNull().hasSizeGreaterThan(0);
    assertThat(actual.getPrivate().getFormat()).isNotBlank();
  }

  @DisplayName("KeyPair 가 String 으로 정상 변환된다.")
  @Test
  void t1() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair given = RsaKeyFactory.generate();

    // when
    AsymmetricKey actual = RsaKeyFactory.generateToString(given);

    // then
    assertThat(actual.publicKey()).isNotBlank().contains(RsaKeyFactory.DEFAULT_PUBLIC_KEY_COMMENT);
    assertThat(actual.privateKey()).isNotBlank().contains(RsaKeyFactory.DEFAULT_PRIVATE_KEY_COMMENT);
  }

  @DisplayName("String Key 가 KeyPair 로 정상 변환 된다.")
  @Test
  void t2() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair expected = RsaKeyFactory.generate();
    AsymmetricKey given = RsaKeyFactory.generateToString(expected);

    // when
    KeyPair actual = RsaKeyFactory.generate(given);

    // then
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(expected.getPublic().getAlgorithm());
    assertThat(actual.getPublic().getFormat()).isEqualTo(expected.getPublic().getFormat());
    assertThat(actual.getPublic().getEncoded()).isEqualTo(expected.getPublic().getEncoded());
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(expected.getPrivate().getAlgorithm());
    assertThat(actual.getPrivate().getFormat()).isEqualTo(expected.getPrivate().getFormat());
    assertThat(actual.getPrivate().getEncoded()).isEqualTo(expected.getPrivate().getEncoded());
  }
}