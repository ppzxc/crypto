package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AsymmetricKeyFactoryTest {

  @BeforeAll
  static void beforeAll() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_created_key_pair() throws NoSuchAlgorithmException, NoSuchProviderException {
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

  @Test
  void should_created_key_pair_to_string() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair given = AsymmetricKeyFactory.generateRsa();

    // when
    AsymmetricKey actual = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKeyType.RSA, given);

    // then
    assertThat(actual.getPublicKey()).isNotBlank().contains(AsymmetricKeyFactory.DEFAULT_PUBLIC_KEY_COMMENT);
    assertThat(actual.getPrivateKey()).isNotBlank().contains(AsymmetricKeyFactory.DEFAULT_PRIVATE_RSA_KEY_COMMENT);
  }

  @Test
  void should_transform_key_pair_form_string()
    throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CryptoException {
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

  @Test
  void should_created_1024_bit_key()
    throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CryptoException {
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

  @Test
  void should_created_2048_bit_key()
    throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CryptoException {
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

  @Test
  void should_created_when_given_asymmetric_key_type() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given, when
    AsymmetricKey actual = AsymmetricKeyFactory.generate(AsymmetricKeyType.RSA);

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getAsymmetricKeyType()).isEqualByComparingTo(AsymmetricKeyType.RSA);
    assertThat(actual.getPublicKey()).isNotBlank();
    assertThat(actual.getPrivateKey()).isNotBlank();
  }
}