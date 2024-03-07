package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class AesCryptoTest {

  @Test
  void should_throw_exception_1() {
    assertThatCode(() -> AesCrypto.builder()
      .secretKeySpec(null)
      .build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_2() {
    assertThatCode(() -> AesCrypto.builder()
      .ivParameterSpec(null)
      .build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_3() {
    assertThatCode(() -> AesCrypto.builder()
      .transformation(null)
      .build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_4() {
    assertThatCode(() -> AesCrypto.builder()
      .cryptoProvider(null)
      .build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_5() {
    assertThatCode(() -> AesCrypto.builder()
      .charset(null)
      .build()).isInstanceOf(NullPointerException.class);
  }

  @Test
  void should_throw_exception_6() {
    assertThatCode(() -> AesCrypto.builder()
      .charset(StandardCharsets.UTF_8)
      .build()).doesNotThrowAnyException();
  }
}