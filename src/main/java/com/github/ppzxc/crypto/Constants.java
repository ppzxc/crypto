package com.github.ppzxc.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public final class Constants {

  public static final SecureRandom SECURE_RANDOM;
  public static final String SHA_1_PRNG = "SHA1PRNG";
  public static final String SUN = "SUN";

  static {
    try {
      SECURE_RANDOM = SecureRandom.getInstance(SHA_1_PRNG, SUN);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  private Constants() {
  }
}
