package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * The type Symmetric key factory.
 */
public final class SymmetricKeyFactory {

  /**
   * The constant ALPHABET.
   */
  public static final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  /**
   * The constant CHARSET.
   */
  public static final Charset CHARSET = StandardCharsets.UTF_8;

  private SymmetricKeyFactory() {
  }

  /**
   * Generate string.
   *
   * @param size the size
   * @return the string
   */
  public static String generate(int size) {
    if (size != 16 && size != 24 && size != 32) {
      throw new IllegalArgumentException("require symmetric key size 16, 24, 32");
    }
    return IntStream.range(0, size)
      .mapToObj(ignored -> String.valueOf(ALPHABET.charAt(Constants.SECURE_RANDOM.nextInt(ALPHABET.length()))))
      .collect(Collectors.joining());
  }

  /**
   * Bit 128 symmetric key.
   *
   * @return the symmetric key
   */
  public static SymmetricKey bit128() {
    return new SymmetricKey(generate(16));
  }

  /**
   * Bit 192 symmetric key.
   *
   * @return the symmetric key
   */
  public static SymmetricKey bit192() {
    return new SymmetricKey(generate(24));
  }

  /**
   * Bit 256 symmetric key.
   *
   * @return the symmetric key
   */
  public static SymmetricKey bit256() {
    return new SymmetricKey(generate(32));
  }
}