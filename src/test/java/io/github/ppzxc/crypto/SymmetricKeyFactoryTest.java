package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SymmetricKeyFactoryTest {

  @ParameterizedTest
  @ValueSource(ints = {16, 24, 32})
  void should_create_symmetric_key(int size) throws NoSuchAlgorithmException {
    // given
    String given = SymmetricKeyFactory.generate(size);

    // when
    assertThat(given).hasSize(size);
    assertThat(given.getBytes(SymmetricKeyFactory.CHARSET)).hasSize(size);
  }

  @Test
  void should_create_16bit_symmetric_key() {
    // given, when
    SymmetricKey actual = SymmetricKeyFactory.bit128();

    // then
    assertThat(actual.getKey()).isNotBlank();
    assertThat(actual.getKeyByteArray()).hasSize(16);
  }

  @Test
  void should_create_24bit_symmetric_key() {
    // given, when
    SymmetricKey actual = SymmetricKeyFactory.bit192();

    // then
    assertThat(actual.getKey()).isNotBlank();
    assertThat(actual.getKeyByteArray()).hasSize(24);
  }

  @Test
  void should_create_32bit_symmetric_key() {
    // given, when
    SymmetricKey actual = SymmetricKeyFactory.bit256();

    // then
    assertThat(actual.getKey()).isNotBlank();
    assertThat(actual.getKeyByteArray()).hasSize(32);
  }
}