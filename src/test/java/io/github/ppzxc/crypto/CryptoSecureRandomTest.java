package io.github.ppzxc.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Constructor;
import java.security.SecureRandom;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CryptoSecureRandomTest {

  @BeforeAll
  static void beforeAll() {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
  }

  @Test
  void should_return_secure_random_when_default_called() {
    // given

    // when
    SecureRandom actual = CryptoSecureRandom.getSecureRandom();

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getAlgorithm()).isEqualTo("SHA1PRNG");
  }

  @Test
  void should_return_secure_random_when_algorithm_is_given() {
    // given
    String algorithm = "SHA1PRNG";

    // when
    SecureRandom actual = CryptoSecureRandom.getSecureRandom(algorithm);

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getAlgorithm()).isEqualTo(algorithm);
  }

  @Test
  void should_return_secure_random_when_algorithm_and_provider_string_are_given() {
    // given
    String algorithm = "SHA1PRNG";
    String provider = "SUN";

    // when
    SecureRandom actual = CryptoSecureRandom.getSecureRandom(algorithm, provider);

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getAlgorithm()).isEqualTo(algorithm);
    assertThat(actual.getProvider().getName()).isEqualTo(provider);
  }

  @Test
  void should_return_secure_random_when_algorithm_and_crypto_provider_are_given() {
    // given
    String algorithm = "NONCEANDIV";
    CryptoProvider provider = CryptoProvider.BOUNCY_CASTLE;

    // when
    SecureRandom actual = CryptoSecureRandom.getSecureRandom(algorithm, provider);

    // then
    assertThat(actual).isNotNull();
    assertThat(actual.getAlgorithm()).isEqualTo(algorithm);
    assertThat(actual.getProvider().getName()).isEqualTo(provider.getCode());
  }

  @Test
  void should_throw_exception_when_invalid_algorithm_is_given() {
    // given
    String invalidAlgorithm = "INVALID_ALGORITHM";

    // when & then
    assertThatThrownBy(() -> CryptoSecureRandom.getSecureRandom(invalidAlgorithm))
      .isInstanceOf(CryptoRuntimeException.class);
  }

  @Test
  void should_throw_exception_when_invalid_provider_is_given() {
    // given
    String algorithm = "SHA1PRNG";
    String invalidProvider = "INVALID_PROVIDER";

    // when & then
    assertThatThrownBy(() -> CryptoSecureRandom.getSecureRandom(algorithm, invalidProvider))
      .isInstanceOf(CryptoRuntimeException.class);
  }

  @Test
  void should_be_able_to_instantiate_private_constructor_via_reflection() throws Exception {
    // given
    Constructor<CryptoSecureRandom> constructor = CryptoSecureRandom.class.getDeclaredConstructor();
    constructor.setAccessible(true);

    // when
    CryptoSecureRandom instance = constructor.newInstance();

    // then
    assertThat(instance).isNotNull();
  }
}
