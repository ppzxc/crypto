package com.github.ppzxc.crypto;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

public final class RandomString {

  private RandomString() {
  }

  public static String giveMeOne() {
    return giveMeOne(512);
  }

  public static String giveMeOne(int origin, int bound) {
    return giveMeOne(ThreadLocalRandom.current().nextInt(origin, bound));
  }

  public static String giveMeOne(int origin, int bound, int... without) {
    while (true) {
      int givenSize = ThreadLocalRandom.current().nextInt(origin, bound);
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
      int randomLimitedInt = leftLimit + (int) (ThreadLocalRandom.current().nextFloat() * (rightLimit - leftLimit + 1));
      buffer.append((char) randomLimitedInt);
    }
    return buffer.toString();
  }
}
