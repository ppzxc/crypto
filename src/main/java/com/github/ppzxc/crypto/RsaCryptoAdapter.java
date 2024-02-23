package com.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import lombok.Builder;
import lombok.NonNull;
import org.bouncycastle.util.encoders.Base64;

@Builder
public final class RsaCryptoAdapter implements RsaCrypto {

  @Builder.Default
  @NonNull
  private Transformation transformation = Transformation.RSA;
  @Builder.Default
  @NonNull
  private Provider provider = Provider.BOUNCY_CASTLE;
  @Builder.Default
  @NonNull
  private Charset charset = StandardCharsets.UTF_8;
  @NonNull
  private PublicKey publicKey;
  @NonNull
  private PrivateKey privateKey;

  @Override
  public byte[] encrypt(byte[] plainText) throws CryptoException {
    try {
      Cipher cipher = Cipher.getInstance(transformation.getCode(), provider.getCode());
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
      Cipher cipher = Cipher.getInstance(transformation.getCode(), provider.getCode());
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
}
