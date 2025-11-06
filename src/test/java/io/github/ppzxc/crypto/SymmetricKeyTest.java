package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.ppzxc.fixh.StringUtils;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SymmetricKeyTest {

  @BeforeAll
  static void beforeAll() {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_occurred_exception_when_null_key() {
    assertThatThrownBy(() -> new SymmetricKey(null))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'SymmetricKey' require not blank");
  }

  @Test
  void should_occurred_exception_when_empty_key() {
    assertThatThrownBy(() -> new SymmetricKey(""))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'SymmetricKey' require not blank");
  }

  @Test
  void should_occurred_exception_when_blank_key() {
    assertThatThrownBy(() -> new SymmetricKey("    "))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessage("'SymmetricKey' require not blank");
  }

  @Test
  void should_return_key_when_input_key() {
    // given
    String expected = StringUtils.giveMeOne();

    // when
    SymmetricKey actual = new SymmetricKey(expected);

    // then
    assertThat(actual.getKey()).isEqualTo(expected);
  }

  @Test
  void should_return_key_when_input_key_bytes() {
    // given
    String expected = StringUtils.giveMeOne();

    // when
    SymmetricKey actual = new SymmetricKey(expected);

    // then
    assertThat(actual.getKeyByteArray()).isEqualTo(expected.getBytes(StandardCharsets.UTF_8));
  }
}