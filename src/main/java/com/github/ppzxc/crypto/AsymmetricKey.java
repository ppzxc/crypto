package com.github.ppzxc.crypto;

public class AsymmetricKey {

  private final String publicKey;
  private final String privateKey;

  private AsymmetricKey(String publicKey, String privateKey) {
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    if (publicKey == null || publicKey.trim().isEmpty()) {
      throw new IllegalArgumentException("'PublicKey' require not blank");
    }
    if (privateKey == null || privateKey.trim().isEmpty()) {
      throw new IllegalArgumentException("'PrivateKey' require not blank");
    }
  }

  public static AsymmetricKey of(String publicKey, String privateKey) {
    return new AsymmetricKey(publicKey, privateKey);
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }
}