package io.github.ppzxc.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public final class CryptoSecureRandom {

  private static final String SHA_1_PRNG = "SHA1PRNG";

  private CryptoSecureRandom() {
  }

  public static SecureRandom getSecureRandom(String algorithm, String provider) {
    try {
      return SecureRandom.getInstance(algorithm, provider);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new CryptoRuntimeException(e);
    }
  }

  public static SecureRandom getSecureRandom(String algorithm) {
    try {
      return SecureRandom.getInstance(algorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new CryptoRuntimeException(e);
    }
  }

  public static SecureRandom getSecureRandom(String algorithm, CryptoProvider cryptoProvider) {
    return getSecureRandom(algorithm, cryptoProvider.getCode());
  }

  public static SecureRandom getSecureRandom() {
    return getSecureRandom(SHA_1_PRNG);
  }
}
