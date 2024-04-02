package io.github.ppzxc.crypto;

public class AsymmetricKey {

  private final Type type;
  private final String publicKey;
  private final String privateKey;

  private AsymmetricKey(Type type, String publicKey, String privateKey) {
    this.type = type;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    if (type == null) {
      throw new IllegalArgumentException("'AsymmetricKey.Type' require not null");
    }
    if (publicKey == null || publicKey.trim().isEmpty()) {
      throw new IllegalArgumentException("'PublicKey' require not blank");
    }
    if (privateKey == null || privateKey.trim().isEmpty()) {
      throw new IllegalArgumentException("'PrivateKey' require not blank");
    }
  }

  public static AsymmetricKey of(Type type, String publicKey, String privateKey) {
    return new AsymmetricKey(type, publicKey, privateKey);
  }

  public Type getType() {
    return type;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public enum Type {
    RSA
  }
}