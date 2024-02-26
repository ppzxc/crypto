package com.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

class AesRandomIvTest {

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 1")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t0(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    byte[] expected = RandomBytes.giveMeOne();

    if (aesArgument.ivSize == 16) {
      // when
      byte[] cipherText = given.encrypt(expected);
      byte[] actual = given.decrypt(cipherText);

      // then
      assertThat(actual).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> given.encrypt(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 2")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t1(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    byte[] expected = RandomBytes.giveMeOne();

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      byte[] actual = given.decrypt(cipherText);

      // then
      assertThat(actual).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 3")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t2(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    byte[] expected = RandomBytes.giveMeOne();

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      String actual = given.decryptToString(cipherText);

      // then
      assertThat(actual).isEqualTo(new String(expected, StandardCharsets.UTF_8));
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 4")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t3(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    byte[] expected = RandomBytes.giveMeOneWithUtf8();

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      String actual = given.decryptToString(cipherText);

      // then
      assertThat(actual.getBytes(StandardCharsets.UTF_8)).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 5")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t4(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    String expected = RandomString.giveMeOne(512);

    if (aesArgument.ivSize == 16) {
      // when
      byte[] cipherText = given.encrypt(expected);
      byte[] actual = given.decrypt(cipherText);

      // then
      assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
    } else {
      assertThatThrownBy(() -> given.encrypt(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 6")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t5(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    String expected = RandomString.giveMeOne(512);

    if (aesArgument.ivSize == 16) {
      // when
      byte[] cipherText = given.encrypt(expected.getBytes(StandardCharsets.UTF_8));
      byte[] actual = given.decrypt(cipherText);

      // then
      assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
    } else {
      assertThatThrownBy(() -> given.encrypt(expected.getBytes(StandardCharsets.UTF_8)))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 7")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t6(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    String expected = RandomString.giveMeOne(512);

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      byte[] actual = given.decrypt(cipherText);

      // then
      assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 8")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t7(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    String expected = RandomString.giveMeOne(512);

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      byte[] actual = given.decrypt(cipherText.getBytes(StandardCharsets.UTF_8));

      // then
      assertThat(actual).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 9")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t8(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    String expected = RandomString.giveMeOne(512);

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      String actual = given.decryptToString(cipherText);

      // then
      assertThat(actual).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  @DisplayName("aes crypto 로 암복호화 할때 iv 값은 16 byte 만 허용된다. 10")
  @ParameterizedTest
  @ArgumentsSource(value = AllArgumentsProvider.class)
  void t9(AesArgument aesArgument) throws CryptoException {
    // given
    Crypto given = create(aesArgument);
    String expected = RandomString.giveMeOne(512);

    if (aesArgument.ivSize == 16) {
      // when
      String cipherText = given.encryptToString(expected);
      String actual = given.decryptToString(cipherText.getBytes(StandardCharsets.UTF_8));

      // then
      assertThat(actual).isEqualTo(expected);
    } else {
      assertThatThrownBy(() -> given.encryptToString(expected))
        .satisfies(exception -> assertThat(exception.getCause()).isInstanceOf(
          InvalidAlgorithmParameterException.class));
    }
  }

  private Crypto create(AesArgument aesArgument) {
    return CryptoFactory.aes(RandomBytes.giveMeOne(aesArgument.keyBit), aesArgument.transformation,
      CryptoProvider.BOUNCY_CASTLE, RandomBytes.giveMeOne(aesArgument.ivSize));
  }

  static class AllArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext extensionContext) throws Exception {
      return Stream.of(
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_CBC_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_CBC_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_CBC_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_CBC_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_CBC_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_CBC_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_CFB_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_CFB_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_CFB_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_CFB_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_CFB_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_CFB_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_OFB_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_OFB_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_OFB_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_OFB_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_OFB_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_OFB_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_CTR_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_CTR_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_CTR_PKCS5PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(16, ivSize, Transformation.AES_CTR_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(24, ivSize, Transformation.AES_CTR_PKCS7PADDING))
          .collect(Collectors.toList()),
        IntStream.rangeClosed(16, 24)
          .mapToObj(ivSize -> new AesArgument(32, ivSize, Transformation.AES_CTR_PKCS7PADDING))
          .collect(Collectors.toList())
      ).flatMap(Collection::stream).map(Arguments::of);
    }
  }

  public static class AesArgument {

    private final int keyBit;
    private final int ivSize;
    private final Transformation transformation;

    public AesArgument(int keyBit, int ivSize, Transformation transformation) {
      this.keyBit = keyBit;
      this.ivSize = ivSize;
      this.transformation = transformation;
    }

    public int getKeyBit() {
      return keyBit;
    }

    public int getIvSize() {
      return ivSize;
    }

    public Transformation getTransformation() {
      return transformation;
    }

    @Override
    public String toString() {
      return "keyBit=" + keyBit + " ivSize=" + ivSize + " transformation=" + transformation;
    }
  }
}