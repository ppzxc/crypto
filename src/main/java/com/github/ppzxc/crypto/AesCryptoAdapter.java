package com.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.Builder;
import lombok.NonNull;
import org.bouncycastle.util.encoders.Base64;

@Builder
public final class AesCryptoAdapter implements AesCrypto {

  @NonNull
  private SecretKeySpec secretKeySpec;
  @NonNull
  private IvParameterSpec ivParameterSpec;
  @NonNull
  private Transformation transformation;
  @NonNull
  private Provider provider;
  @Builder.Default
  @NonNull
  private Charset charset = StandardCharsets.UTF_8;

  @Override
  public byte[] encrypt(byte[] plainText) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance(transformation.getCode(), provider.getCode());
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
      Cipher cipher = Cipher.getInstance(transformation.getCode(), provider.getCode());
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
}
