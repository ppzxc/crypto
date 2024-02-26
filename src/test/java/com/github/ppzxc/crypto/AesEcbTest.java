package com.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

class AesEcbTest {

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 1")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t0(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = RandomBytes.giveMeOne();

    // when
    byte[] cipherText = given.encrypt(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 2")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t1(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = RandomBytes.giveMeOne();

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 3")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t2(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = RandomBytes.giveMeOne();

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(new String(expected, StandardCharsets.UTF_8));
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 4")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t3(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    byte[] expected = RandomBytes.giveMeOneWithUtf8();

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual.getBytes(StandardCharsets.UTF_8)).isEqualTo(expected);
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 5")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t4(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = RandomString.giveMeOne(512);

    // when
    byte[] cipherText = given.encrypt(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 6")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t5(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = RandomString.giveMeOne(512);

    // when
    byte[] cipherText = given.encrypt(expected.getBytes(StandardCharsets.UTF_8));
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 7")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t6(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText);

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 8")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t7(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    byte[] actual = given.decrypt(cipherText.getBytes(StandardCharsets.UTF_8));

    // then
    assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 9")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t8(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText);

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes crypto 로 암/복호화 할 수 있다. 10")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t9(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
      aesArgument.provider);
    String expected = RandomString.giveMeOne(512);

    // when
    String cipherText = given.encryptToString(expected);
    String actual = given.decryptToString(cipherText.getBytes(StandardCharsets.UTF_8));

    // then
    assertThat(actual).isEqualTo(expected);
  }

  @DisplayName("aes 의 IV 최소값 테스트")
  @ParameterizedTest
  @ArgumentsSource(value = AesArgumentsProvider.class)
  void t10(AesArgument aesArgument) throws CryptoException {
    for (int i = 0; i <= 256; i++) {
      try {
        CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyLength), aesArgument.transformation,
          aesArgument.provider, RandomBytes.giveMeOne(i));
      } catch (Exception e) {
        fail(e.getMessage());
      }
    }
  }

  static class AesArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) throws Exception {
      return Stream.of(new AesArgument(16, Transformation.AES_ECB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_ECB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_ECB_PKCS5PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(16, Transformation.AES_ECB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(24, Transformation.AES_ECB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE),
          new AesArgument(32, Transformation.AES_ECB_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE))
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