package com.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SymmetricKeyFactoryTest {

  @ParameterizedTest
  @ValueSource(ints = {16, 24, 32})
  void should_create_symmetric_key(int size) throws NoSuchAlgorithmException {
    assertThat(SymmetricKeyFactory.generate(size)).hasSize(size);
    assertThat(SymmetricKeyFactory.generate(size).getBytes(SymmetricKeyFactory.CHARSET)).hasSize(size);
  }
}