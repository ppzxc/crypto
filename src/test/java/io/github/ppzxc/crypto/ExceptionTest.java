package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ExceptionTest {

  @Test
  void should_create_CryptoException_with_various_constructors() {
    // given
    Exception cause = new RuntimeException("cause");
    String message = "message";

    // when
    CryptoException ex1 = new CryptoException();
    CryptoException ex2 = new CryptoException(message);
    CryptoException ex3 = new CryptoException(message, cause);
    CryptoException ex4 = new CryptoException(cause);

    // then
    assertThat(ex1).isNotNull();
    assertThat(ex2.getMessage()).isEqualTo(message);
    assertThat(ex3.getMessage()).isEqualTo(message);
    assertThat(ex3.getCause()).isEqualTo(cause);
    assertThat(ex4.getCause()).isEqualTo(cause);
  }

  @Test
  void should_create_CryptoRuntimeException_with_various_constructors() {
    // given
    Exception cause = new RuntimeException("cause");
    String message = "message";

    // when
    CryptoRuntimeException ex1 = new CryptoRuntimeException();
    CryptoRuntimeException ex2 = new CryptoRuntimeException(message);
    CryptoRuntimeException ex3 = new CryptoRuntimeException(message, cause);
    CryptoRuntimeException ex4 = new CryptoRuntimeException(cause);
    CryptoRuntimeException ex5 = new CryptoRuntimeException(message, cause, true, true);
    CryptoRuntimeException ex6 = CryptoRuntimeException.notSupportedDecrypt();

    // then
    assertThat(ex1).isNotNull();
    assertThat(ex2.getMessage()).isEqualTo(message);
    assertThat(ex3.getMessage()).isEqualTo(message);
    assertThat(ex3.getCause()).isEqualTo(cause);
    assertThat(ex4.getCause()).isEqualTo(cause);
    assertThat(ex5.getMessage()).isEqualTo(message);
    assertThat(ex5.getCause()).isEqualTo(cause);
    assertThat(ex6.getMessage()).isEqualTo("not supported decrypt");
  }

  @Test
  void should_create_CryptoException_not_supported_decrypt() {
    // given & when
    CryptoException ex = CryptoException.notSupportedDecrypt();

    // then
    assertThat(ex.getMessage()).isEqualTo("not supported decrypt");
  }

  @Test
  void should_create_CryptoException_with_all_params() {
    // given
    Exception cause = new RuntimeException("cause");
    String message = "message";

    // when
    CryptoException ex = new CryptoException(message, cause, true, true);

    // then
    assertThat(ex.getMessage()).isEqualTo(message);
    assertThat(ex.getCause()).isEqualTo(cause);
  }
}
