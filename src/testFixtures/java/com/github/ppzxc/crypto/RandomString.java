package com.github.ppzxc.crypto;

import java.security.SecureRandom;
import java.util.Arrays;

public final class RandomString {

  public static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private RandomString() {
  }

  public static String giveMeOne() {
    return giveMeOne(512);
  }

  public static String giveMeOne(int origin, int bound) {
    return giveMeOne(SECURE_RANDOM.nextInt(origin, bound));
  }

  public static String giveMeOne(int origin, int bound, int... without) {
    while (true) {
      int givenSize = SECURE_RANDOM.nextInt(origin, bound);
      if (Arrays.stream(without).noneMatch(w -> w == givenSize)) {
        return giveMeOne(givenSize);
      }
    }
  }

  public static String giveMeOne(int length) {
    int leftLimit = 97; // letter 'a'
    int rightLimit = 122; // letter 'z'
    StringBuilder buffer = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
      int randomLimitedInt = leftLimit + (int)
        (SECURE_RANDOM.nextFloat() * (rightLimit - leftLimit + 1));
      buffer.append((char) randomLimitedInt);
    }
    return buffer.toString();
  }
}
