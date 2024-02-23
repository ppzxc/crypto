package com.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Base64;

public final class SymmetricKeyFactory {

  private static final SecureRandom SECURE_RANDOM;
  public static final Charset CHARSET = StandardCharsets.UTF_8;
  public static final String SHA_1_PRNG = "SHA1PRNG";
  public static final String SUN = "SUN";

  static {
    try {
      SECURE_RANDOM = SecureRandom.getInstance(SHA_1_PRNG, SUN);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new RuntimeException(e);
    }
  }

  private SymmetricKeyFactory() {
  }

  public static byte[] generate(int size) {
    byte[] temp = new byte[size];
    SECURE_RANDOM.nextBytes(temp);
    return Base64.encode(temp);
  }

  public static String generateToString(int size, Charset charset) {
    return new String(generate(size), charset);
  }

  public static String generateToString(int size) {
    return generateToString(size, CHARSET);
  }

  public static SymmetricKey bit128() {
    return new SymmetricKey(generateToString(16));
  }

  public static SymmetricKey bit192() {
    return new SymmetricKey(generateToString(24));
  }

  public static SymmetricKey bit256() {
    return new SymmetricKey(generateToString(32));
  }
}