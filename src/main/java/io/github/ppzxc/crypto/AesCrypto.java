package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;

public final class AesCrypto implements Crypto {

  private final SecretKeySpec secretKeySpec;
  private final IvParameterSpec ivParameterSpec;
  private final Transformation transformation;
  private final CryptoProvider cryptoProvider;
  private final Charset charset;

  private AesCrypto(SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec, Transformation transformation,
    CryptoProvider cryptoProvider, Charset charset) {
    this.secretKeySpec = secretKeySpec;
    this.ivParameterSpec = ivParameterSpec;
    this.transformation = transformation;
    this.cryptoProvider = cryptoProvider;
    this.charset = charset;
  }

  @Override
  public byte[] encrypt(byte[] plainText) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance(transformation.getCode(), cryptoProvider.getCode());
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
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
  public String encryptToString(String plainText) throws CryptoException {
    return new String(encrypt(plainText.getBytes(charset)), charset);
  }

  @Override
  public String encryptToString(byte[] plainText) throws CryptoException {
    return new String(encrypt(plainText), charset);
  }

  @Override
  public byte[] decrypt(byte[] cipherText) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance(transformation.getCode(), cryptoProvider.getCode());
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
      return cipher.doFinal(Base64.decode(cipherText));
    } catch (Exception e) {
      throw new CryptoException(e);
    }
  }

  @Override
  public String decryptToString(byte[] cipherText) throws CryptoException {
    return new String(decrypt(cipherText), charset);
  }

  @Override
  public byte[] decrypt(String cipherText) throws CryptoException {
    return decrypt(cipherText.getBytes(charset));
  }

  @Override
  public String decryptToString(String cipherText) throws CryptoException {
    return new String(decrypt(cipherText.getBytes(charset)), charset);
  }

  public static AesCryptoBuilder builder() {
    return new AesCryptoBuilder();
  }

  public static class AesCryptoBuilder {

    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;
    private Transformation transformation;
    private CryptoProvider cryptoProvider = CryptoProvider.BOUNCY_CASTLE;
    private Charset charset = StandardCharsets.UTF_8;

    AesCryptoBuilder() {
    }

    public AesCryptoBuilder secretKeySpec(SecretKeySpec secretKeySpec) {
      if (secretKeySpec == null) {
        throw new NullPointerException("secretKeySpec is marked non-null but is null");
      } else {
        this.secretKeySpec = secretKeySpec;
        return this;
      }
    }

    public AesCryptoBuilder ivParameterSpec(IvParameterSpec ivParameterSpec) {
      if (ivParameterSpec == null) {
        throw new NullPointerException("ivParameterSpec is marked non-null but is null");
      } else {
        this.ivParameterSpec = ivParameterSpec;
        return this;
      }
    }

    public AesCryptoBuilder transformation(Transformation transformation) {
      if (transformation == null) {
        throw new NullPointerException("transformation is marked non-null but is null");
      } else {
        this.transformation = transformation;
        return this;
      }
    }

    public AesCryptoBuilder cryptoProvider(CryptoProvider cryptoProvider) {
      if (cryptoProvider == null) {
        throw new NullPointerException("cryptoProvider is marked non-null but is null");
      } else {
        this.cryptoProvider = cryptoProvider;
        return this;
      }
    }

    public AesCryptoBuilder charset(Charset charset) {
      if (charset == null) {
        throw new NullPointerException("charset is marked non-null but is null");
      } else {
        this.charset = charset;
        return this;
      }
    }

    public AesCrypto build() {
      return new AesCrypto(secretKeySpec, ivParameterSpec, transformation, cryptoProvider, charset);
    }
  }
}
