package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import javax.crypto.Cipher;
import org.bouncycastle.util.encoders.Base64;

public final class RsaEncryptor implements Crypto {

  private final Transformation transformation;
  private final CryptoProvider cryptoProvider;
  private final Charset charset;
  private final PublicKey publicKey;

  private RsaEncryptor(Transformation transformation, CryptoProvider cryptoProvider, Charset charset, PublicKey publicKey) {
    this.transformation = transformation;
    this.cryptoProvider = cryptoProvider;
    this.charset = charset;
    this.publicKey = publicKey;
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
    throw CryptoException.notSupportedDecrypt();
  }

  @Override
  public byte[] decrypt(String cipherText) throws CryptoException {
    throw CryptoException.notSupportedDecrypt();
  }

  @Override
  public String decryptToString(byte[] cipherText) throws CryptoException {
    throw CryptoException.notSupportedDecrypt();
  }

  @Override
  public String decryptToString(String cipherText) throws CryptoException {
    throw CryptoException.notSupportedDecrypt();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private Transformation transformation = Transformation.RSA;
    private CryptoProvider cryptoProvider = CryptoProvider.BOUNCY_CASTLE;
    private Charset charset = StandardCharsets.UTF_8;
    private PublicKey publicKey;

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

    public RsaEncryptor build() {
      return new RsaEncryptor(transformation, cryptoProvider, charset, publicKey);
    }
  }
}
