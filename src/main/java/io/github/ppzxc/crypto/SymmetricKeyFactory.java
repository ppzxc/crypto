package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public final class SymmetricKeyFactory {

  public static final String ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  public static final Charset CHARSET = StandardCharsets.UTF_8;

  private SymmetricKeyFactory() {
  }

  public static String generate(int size) {
    if (size != 16 && size != 24 && size != 32) {
      throw new IllegalArgumentException("require symmetric key size 16, 24, 32");
    }
    return IntStream.range(0, size)
        .mapToObj(ignored -> String.valueOf(
            ALPHABET.charAt(CryptoSecureRandom.getSecureRandom().nextInt(ALPHABET.length()))))
        .collect(Collectors.joining());
  }

  public static SymmetricKey bit128() {
    return new SymmetricKey(generate(16));
  }

  public static SymmetricKey bit192() {
    return new SymmetricKey(generate(24));
  }

  public static SymmetricKey bit256() {
    return new SymmetricKey(generate(32));
  }
}