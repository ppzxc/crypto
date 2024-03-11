package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.ppzxc.crypto.AesCrypto.AesCryptoBuilder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AesCryptoTest {

  private AesCryptoBuilder builder;

  @BeforeAll
  static void beforeAll() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @BeforeEach
  void setUp() {
    builder = AesCrypto.builder();
  }

  @Test
  void should_throw_exception_1() {
    assertThatCode(() -> builder.secretKeySpec(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_2() {
    assertThatCode(() -> builder.ivParameterSpec(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_3() {
    assertThatCode(() -> builder.transformation(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_4() {
    assertThatCode(() -> builder.cryptoProvider(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_5() {
    assertThatCode(() -> builder.charset(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_6() {
    assertThatCode(() -> builder.charset(StandardCharsets.UTF_8)).doesNotThrowAnyException();
  }
}