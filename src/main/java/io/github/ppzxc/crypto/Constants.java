package io.github.ppzxc.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * The type Constants.
 */
public final class Constants {

  /**
   * The constant SECURE_RANDOM.
   */
  public static final SecureRandom SECURE_RANDOM;
  /**
   * The constant SHA_1_PRNG.
   */
  public static final String SHA_1_PRNG = "SHA1PRNG";
  /**
   * The constant SUN.
   */
  public static final String SUN = "SUN";

  static {
    try {
      SECURE_RANDOM = SecureRandom.getInstance(SHA_1_PRNG, SUN);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private Constants() {
  }
}
