package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

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
      return Base64.getEncoder().encode(cipher.doFinal(plainText));
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
      return cipher.doFinal(Base64.getDecoder().decode(cipherText));
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
    return new String(decrypt(cipherText.getBytes(charset)), charset);
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private Transformation transformation = Transformation.RSA_ECB_PKCS1PADDING;
    private CryptoProvider cryptoProvider = CryptoProvider.BOUNCY_CASTLE;
    private Charset charset = StandardCharsets.UTF_8;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    Builder() {
    }

    public Builder transformation(Transformation transformation) {
      if (transformation == null) {
        throw new NullPointerException("transformation is marked non-null but is null");
      } else {
        this.transformation = transformation;
        return this;
      }
    }

    public Builder cryptoProvider(CryptoProvider cryptoProvider) {
      if (cryptoProvider == null) {
        throw new NullPointerException("cryptoProvider is marked non-null but is null");
      } else {
        this.cryptoProvider = cryptoProvider;
        return this;
      }
    }

    public Builder charset(Charset charset) {
      if (charset == null) {
        throw new NullPointerException("charset is marked non-null but is null");
      } else {
        this.charset = charset;
        return this;
      }
    }

    public Builder publicKey(PublicKey publicKey) {
      if (publicKey == null) {
        throw new NullPointerException("publicKey is marked non-null but is null");
      } else {
        this.publicKey = publicKey;
        return this;
      }
    }

    public Builder privateKey(PrivateKey privateKey) {
      if (privateKey == null) {
        throw new NullPointerException("privateKey is marked non-null but is null");
      } else {
        this.privateKey = privateKey;
        return this;
      }
    }

    public RsaCrypto build() {
      return new RsaCrypto(transformation, cryptoProvider, charset, publicKey, privateKey);
    }
  }
}
