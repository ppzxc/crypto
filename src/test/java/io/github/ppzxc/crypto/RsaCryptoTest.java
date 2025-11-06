package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.crypto.RsaCrypto.Builder;
import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.StringUtils;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

class RsaCryptoTest {

  @BeforeAll
  static void beforeAll() {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_throw_exception_when_invalid_byte_array(RsaArgument rsaArgument)
    throws NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    byte[] plainText = null;

    // when, then
    assertThatCode(() -> crypto.encrypt(plainText)).isInstanceOf(CryptoException.class);
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_encrypt_byte_array_to_byte_array(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    byte[] plainText = ByteArrayUtils.giveMeOne(48);

    // when
    byte[] cipherText = crypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText);
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_encrypt_string_to_byte_array(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    String plainText = StringUtils.giveMeOne(48);

    // when
    byte[] cipherText = crypto.encrypt(plainText);

    // then
    assertThat(cipherText).isNotEqualTo(plainText.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_throw_exception_when_invalid_cipher_text(RsaArgument rsaArgument)
    throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    assertThatCode(() -> crypto.decrypt(ByteArrayUtils.giveMeOne(1))).isInstanceOf(CryptoException.class);
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_decrypt_byte_array_to_byte_array(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    byte[] expected = ByteArrayUtils.giveMeOne(48);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_decrypt_string_to_byte_array(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    String expected = StringUtils.giveMeOne(48);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_encrypt_byte_array_to_string(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    byte[] expected = ByteArrayUtils.giveMeOne(48);
    String cipherText = crypto.encryptToString(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_encrypt_string_to_string(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    String expected = StringUtils.giveMeOne(48);
    String cipherText = crypto.encryptToString(expected);

    // when
    byte[] actual = crypto.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = RsaArgumentsProvider.class)
  void should_decrypt_byte_array_to_string(RsaArgument rsaArgument)
    throws CryptoException, NoSuchAlgorithmException, NoSuchProviderException {
    // given
    KeyPair keyPair = AsymmetricKeyFactory.generateRsa(rsaArgument.keyLength);
    Crypto crypto = RsaCrypto.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
    byte[] expected = ByteArrayUtils.giveMeOne(48);
    byte[] cipherText = crypto.encrypt(expected);

    // when
    String actual = crypto.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(new String(expected, StandardCharsets.UTF_8));
  }

  @Test
  void should_throw_exception_when_null_transformation() {
    // given
    Builder given = RsaCrypto.builder();

    // when, then
    assertThatCode(() -> given.transformation(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_null_provider() {
    // given
    Builder given = RsaCrypto.builder();
    given.transformation(Transformation.RSA_ECB_PKCS1PADDING);

    // when, then
    assertThatCode(() -> given.cryptoProvider(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_provider() {
    // given
    Builder given = RsaCrypto.builder();
    given.transformation(Transformation.RSA_ECB_PKCS1PADDING);
    given.cryptoProvider(CryptoProvider.BOUNCY_CASTLE);

    // when, then
    assertThatCode(given::build).doesNotThrowAnyException();
  }

  @Test
  void should_throw_exception_when_null_charset() {
    // given
    Builder given = RsaCrypto.builder();
    given.transformation(Transformation.RSA_ECB_PKCS1PADDING);
    given.cryptoProvider(CryptoProvider.BOUNCY_CASTLE);

    // when, then
    assertThatCode(() -> given.charset(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_provider_2() {
    assertThatCode(() -> RsaCrypto.builder()
      .transformation(Transformation.RSA_ECB_PKCS1PADDING)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8)
      .build()).doesNotThrowAnyException();
  }

  @Test
  void should_throw_exception_when_not_null_public_key() {
    // given
    Builder given = RsaCrypto.builder()
      .transformation(Transformation.RSA_ECB_PKCS1PADDING)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8);

    // when, then
    assertThatCode(() -> given.publicKey(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_when_not_null_private_key() {
    // given
    Builder given = RsaCrypto.builder()
      .transformation(Transformation.RSA_ECB_PKCS1PADDING)
      .cryptoProvider(CryptoProvider.BOUNCY_CASTLE)
      .charset(StandardCharsets.UTF_8);

    // when, then
    assertThatCode(() -> given.privateKey(null)).isInstanceOf(NullPointerException.class);
  }

  static class RsaArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) {
      return Stream.of(
          new RsaArgument(512, Transformation.RSA_NONE_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(1024, Transformation.RSA_NONE_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(2048, Transformation.RSA_NONE_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(4096, Transformation.RSA_NONE_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(512, Transformation.RSA_ECB_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(1024, Transformation.RSA_ECB_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(2048, Transformation.RSA_ECB_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE),
          new RsaArgument(4096, Transformation.RSA_ECB_PKCS1PADDING, CryptoProvider.BOUNCY_CASTLE)
        ).map(Arguments::of);
    }
  }

  static class RsaArgument {

    private final int keyLength;
    private final Transformation transformation;
    private final CryptoProvider provider;

    public RsaArgument(int keyLength, Transformation transformation, CryptoProvider provider) {
      this.keyLength = keyLength;
      this.transformation = transformation;
      this.provider = provider;
    }

    public int getKeyLength() {
      return keyLength;
    }

    public Transformation getTransformation() {
      return transformation;
    }

    public CryptoProvider getProvider() {
      return provider;
    }

    @Override
    public String toString() {
      return "keyLength=" + keyLength + " transformation=" + transformation + " provider=" + provider;
    }
  }
}