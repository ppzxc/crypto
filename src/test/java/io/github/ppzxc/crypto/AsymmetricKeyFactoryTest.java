package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AsymmetricKeyFactoryTest {

  @BeforeAll
  static void beforeAll() {
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
    assertThat(actual.getPublic().getAlgorithm()).isEqualTo(AsymmetricKey.Type.RSA.name());
    assertThat(actual.getPublic().getEncoded()).isNotNull().hasSizeGreaterThan(0);
    assertThat(actual.getPublic().getFormat()).isNotBlank();
    assertThat(actual.getPrivate()).isNotNull();
    assertThat(actual.getPrivate()).isNotNull();
    assertThat(actual.getPrivate().getAlgorithm()).isEqualTo(AsymmetricKey.Type.RSA.name());
    assertThat(actual.getPrivate().getEncoded()).isNotNull().hasSizeGreaterThan(0);
    assertThat(actual.getPrivate().getFormat()).isNotBlank();
  }

  @Test
  void should_created_key_pair_to_string() throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    // given
    KeyPair given = AsymmetricKeyFactory.generateRsa();

    // when
    AsymmetricKey actual = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKey.Type.RSA, given);

    // then
    assertThat(actual.getPublicKey()).isNotBlank().contains("PUBLIC_KEY_TYPE");
    assertThat(actual.getPrivateKey()).isNotBlank().contains("PRIVATE_KEY_TYPE");
  }

  @Test
  void should_transform_key_pair_form_string()
    throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CryptoException {
    // given
    KeyPair expected = AsymmetricKeyFactory.generateRsa();
    AsymmetricKey given = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKey.Type.RSA, expected);

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
    AsymmetricKey given = AsymmetricKeyFactory.toAsymmetricKey(AsymmetricKey.Type.RSA, expected);

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
  void should_throw_exception_when_instantiate_private_constructor()
    throws NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
    // given
    Constructor<AsymmetricKeyFactory> constructor = AsymmetricKeyFactory.class.getDeclaredConstructor();
    constructor.setAccessible(true);

    // when & then
    assertThat(constructor.newInstance()).isNotNull();
  }

  @Test
  void should_throw_exception_when_invalid_key_is_given() {
    // given
    String invalidKey = "INVALID";

    // when & then
    assertThatThrownBy(() -> AsymmetricKeyFactory.toPublicKey(AsymmetricKey.Type.RSA, invalidKey, X509EncodedKeySpec::new))
      .isNotNull();
    assertThatThrownBy(() -> AsymmetricKeyFactory.toPrivateKey(AsymmetricKey.Type.RSA, invalidKey, PKCS8EncodedKeySpec::new))
      .isNotNull();
  }

  @Test
  void should_return_asymmetric_key_when_type_is_given() throws Exception {
    // given
    AsymmetricKey.Type type = AsymmetricKey.Type.RSA;

    // when
    AsymmetricKey actual = AsymmetricKeyFactory.generate(type);

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getType()).isEqualTo(type);
  }
}