package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import org.bouncycastle.util.encoders.Base64;

/**
 * The type Rsa crypto.
 */
public final class RsaCrypto implements Crypto {

  private final Transformation transformation;
  private final CryptoProvider cryptoProvider;
  private final Charset charset;
  private final PublicKey publicKey;
  private final PrivateKey privateKey;

  private RsaCrypto(Transformation transformation, CryptoProvider cryptoProvider, Charset charset, PublicKey publicKey,
    PrivateKey privateKey) {
    this.transformation = transformation;
    this.cryptoProvider = cryptoProvider;
    this.charset = charset;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
  }

  @Override
  public byte[] encrypt(byte[] plainText) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance(transformation.getCode(), cryptoProvider.getCode());
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      return Base64.encode(cipher.doFinal(plainText));
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  @Override
  public byte[] encrypt(String plainText) throws CryptoException {
    return encrypt(plainText.getBytes(charset));
  }

  @Override
  public String encryptToString(byte[] plainText) throws CryptoException {
    return new String(encrypt(plainText), charset);
  }

  @Override
  public String encryptToString(String plainText) throws CryptoException {
    return new String(encrypt(plainText.getBytes(charset)), charset);
  }

  @Override
  public byte[] decrypt(byte[] cipherText) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance(transformation.getCode(), cryptoProvider.getCode());
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      return cipher.doFinal(Base64.decode(cipherText));
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  @Override
  public byte[] decrypt(String cipherText) throws CryptoException {
    return decrypt(cipherText.getBytes(charset));
  }

  @Override
  public String decryptToString(byte[] cipherText) throws CryptoException {
    return new String(decrypt(cipherText), charset);
  }

  @Override
  public String decryptToString(String cipherText) throws CryptoException {
    return new String(cipherText.getBytes(charset), charset);
  }

  /**
   * Builder rsa crypto builder.
   *
   * @return the rsa crypto builder
   */
  public static RsaCryptoBuilder builder() {
    return new RsaCryptoBuilder();
  }

  /**
   * The type Rsa crypto builder.
   */
  public static class RsaCryptoBuilder {

    private Transformation transformation = Transformation.RSA;
    private CryptoProvider cryptoProvider = CryptoProvider.BOUNCY_CASTLE;
    private Charset charset = StandardCharsets.UTF_8;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    /**
     * Instantiates a new Rsa crypto builder.
     */
    RsaCryptoBuilder() {
    }

    /**
     * Transformation rsa crypto builder.
     *
     * @param transformation the transformation
     * @return the rsa crypto builder
     */
    public RsaCryptoBuilder transformation(Transformation transformation) {
      if (transformation == null) {
        throw new NullPointerException("transformation is marked non-null but is null");
      } else {
        this.transformation = transformation;
        return this;
      }
    }

    /**
     * Crypto provider rsa crypto builder.
     *
     * @param cryptoProvider the crypto provider
     * @return the rsa crypto builder
     */
    public RsaCryptoBuilder cryptoProvider(CryptoProvider cryptoProvider) {
      if (cryptoProvider == null) {
        throw new NullPointerException("cryptoProvider is marked non-null but is null");
      } else {
        this.cryptoProvider = cryptoProvider;
        return this;
      }
    }

    /**
     * Charset rsa crypto builder.
     *
     * @param charset the charset
     * @return the rsa crypto builder
     */
    public RsaCryptoBuilder charset(Charset charset) {
      if (charset == null) {
        throw new NullPointerException("charset is marked non-null but is null");
      } else {
        this.charset = charset;
        return this;
      }
    }

    /**
     * Public key rsa crypto builder.
     *
     * @param publicKey the public key
     * @return the rsa crypto builder
     */
    public RsaCryptoBuilder publicKey(PublicKey publicKey) {
      if (publicKey == null) {
        throw new NullPointerException("publicKey is marked non-null but is null");
      } else {
        this.publicKey = publicKey;
        return this;
      }
    }

    /**
     * Private key rsa crypto builder.
     *
     * @param privateKey the private key
     * @return the rsa crypto builder
     */
    public RsaCryptoBuilder privateKey(PrivateKey privateKey) {
      if (privateKey == null) {
        throw new NullPointerException("privateKey is marked non-null but is null");
      } else {
        this.privateKey = privateKey;
        return this;
      }
    }

    /**
     * Build rsa crypto.
     *
     * @return the rsa crypto
     */
    public RsaCrypto build() {
      return new RsaCrypto(transformation, cryptoProvider, charset, publicKey, privateKey);
    }
  }
}
