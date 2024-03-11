package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThatCode;

import org.junit.jupiter.api.Test;

class CryptoProviderTest {

  @Test
  void should_add_bouncy_castle() {
    // given
    CryptoProvider given = CryptoProvider.BOUNCY_CASTLE;

    // when, then
    assertThatCode(given::addProvider).doesNotThrowAnyException();
  }

  @Test
  void should_add_none() {
    // given
    CryptoProvider given = CryptoProvider.NONE;

    // when, then
    assertThatCode(given::addProvider).doesNotThrowAnyException();
  }
}