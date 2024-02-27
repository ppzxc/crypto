package io.github.ppzxc.crypto;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class RandomBytes {

  public static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private RandomBytes() {
  }

  public static byte[] giveMeOne(int length) {
    byte[] bytes = new byte[length];
    SECURE_RANDOM.nextBytes(bytes);
    return bytes;
  }

  public static byte[] giveMeOneWithUtf8(int length) {
    return new String(giveMeOne(length), StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8);
  }

  public static byte[] giveMeOne() {
    return giveMeOne(1024);
  }

  public static byte[] giveMeOneWithUtf8() {
    return giveMeOneWithUtf8(1024);
  }
}
