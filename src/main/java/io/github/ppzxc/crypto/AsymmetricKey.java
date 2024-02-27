package io.github.ppzxc.crypto;

/**
 * The type Asymmetric key.
 */
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

  /**
   * Of asymmetric key.
   *
   * @param asymmetricKeyType the asymmetric key type
   * @param publicKey         the public key
   * @param privateKey        the private key
   * @return the asymmetric key
   */
  public static AsymmetricKey of(AsymmetricKeyType asymmetricKeyType, String publicKey, String privateKey) {
    return new AsymmetricKey(asymmetricKeyType, publicKey, privateKey);
  }

  /**
   * Gets asymmetric key type.
   *
   * @return the asymmetric key type
   */
  public AsymmetricKeyType getAsymmetricKeyType() {
    return asymmetricKeyType;
  }

  /**
   * Gets public key.
   *
   * @return the public key
   */
  public String getPublicKey() {
    return publicKey;
  }

  /**
   * Gets private key.
   *
   * @return the private key
   */
  public String getPrivateKey() {
    return privateKey;
  }
}