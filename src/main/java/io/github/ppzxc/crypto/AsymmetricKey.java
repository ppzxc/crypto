package io.github.ppzxc.crypto;

public class AsymmetricKey {

  private final AsymmetricKeyType asymmetricKeyType;
  private final String publicKey;
  private final String privateKey;

  private AsymmetricKey(AsymmetricKeyType asymmetricKeyType, String publicKey, String privateKey) {
    this.asymmetricKeyType = asymmetricKeyType;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    if (asymmetricKeyType == null) {
      throw new IllegalArgumentException("'AsymmetricKeyType' require not null");
    }
    if (publicKey == null || publicKey.trim().isEmpty()) {
      throw new IllegalArgumentException("'PublicKey' require not blank");
    }
    if (privateKey == null || privateKey.trim().isEmpty()) {
      throw new IllegalArgumentException("'PrivateKey' require not blank");
    }
  }

  public static AsymmetricKey of(AsymmetricKeyType asymmetricKeyType, String publicKey, String privateKey) {
    return new AsymmetricKey(asymmetricKeyType, publicKey, privateKey);
  }

  public AsymmetricKeyType getAsymmetricKeyType() {
    return asymmetricKeyType;
  }

  public String getPublicKey() {
    return publicKey;
  }

  public String getPrivateKey() {
    return privateKey;
  }
}