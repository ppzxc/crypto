package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.fixh.ByteArrayUtils;
import io.github.ppzxc.fixh.StringUtils;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

class AesTest {

  @BeforeAll
  static void beforeAll() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_1(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = ByteArrayUtils.giveMeOne();

    // when
    byte[] cipherText = given.encrypt(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_2(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = ByteArrayUtils.giveMeOne();

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_3(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = ByteArrayUtils.giveMeOne();

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(new String(expected, StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_4(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = ByteArrayUtils.giveMeOneWithUtf8();

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual.getBytes(StandardCharsets.UTF_8)).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_5(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = StringUtils.giveMeOne(512);

    // when
    byte[] cipherText = given.encrypt(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_6(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = StringUtils.giveMeOne(512);

    // when
    byte[] cipherText = given.encrypt(expected.getBytes(StandardCharsets.UTF_8));
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_7(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = StringUtils.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_8(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = StringUtils.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText.getBytes(StandardCharsets.UTF_8));

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_9(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = StringUtils.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_10(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = StringUtils.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText.getBytes(StandardCharsets.UTF_8));

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void should_encryption_and_decryption_when_use_aes_11(AesArgument aesArgument) {
    for (int i = 0; i <= 256; i++) {
      int finalI = i;
      assertThatCode(
        () -> CryptoFactory.aes(ByteArrayUtils.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
          aesArgument.provider, ByteArrayUtils.giveMeOne(finalI))).doesNotThrowAnyException();
    }
  }

  @Test
  void should_throw_exception_when_decrypt() {
    assertThatCode(() -> CryptoFactory.aes256().decrypt(new byte[]{'a'})).isInstanceOf(CryptoException.class);
  }

  static class AesArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) {
      return Stream.of(
          new AesArgument(16, Transformation.AES_ECB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_ECB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_ECB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_ECB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_ECB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_ECB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_CBC_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_CBC_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_CBC_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_CBC_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_CBC_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_CBC_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_CFB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_CFB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_CFB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_CFB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_CFB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_CFB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_OFB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_OFB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_OFB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_OFB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_OFB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_OFB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_CTR_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_CTR_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_CTR_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_CTR_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_CTR_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_CTR_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE)
        )
        .map(Arguments::of);
    }
  }

  static class AesArgument {

    private final int keyLength;
    private final Transformation transformation;
    private final CryptoProvider provider;

    public AesArgument(int keyLength, Transformation transformation, CryptoProvider provider) {
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