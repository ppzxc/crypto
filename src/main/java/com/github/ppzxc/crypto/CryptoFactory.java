package com.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class CryptoFactory {

  public static final Charset CHARSET = StandardCharsets.UTF_8;
  public static final TransformationType ALGORITHM_TYPE = TransformationType.ADVANCED_ENCRYPTION_STANDARD;
  public static final Provider AES_DEFAULT_PROVIDER = Provider.BOUNCY_CASTLE;
  public static final Transformation AES_DEFAULT_TRANSFORMATION = Transformation.AES_CBC_PKCS5PADDING;
  public static final String AES_DEFAULT_KEY_128BIT = "nanoitSecretKeys";
  public static final String AES_DEFAULT_KEY_192BIT = "nanoitSecretKeysNanoitSe";
  public static final String AES_DEFAULT_KEY_256BIT = "nanoitSecretKeysNanoitSecretKeys";
  public static final String AES_DEFAULT_IV_STRING = "nanoitDefaultIvs";
  public static final byte[] AES_DEFAULT_IV = AES_DEFAULT_IV_STRING.getBytes(CHARSET);

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private CryptoFactory() {
  }

  public static AesCrypto aes(byte[] key, TransformationType transformationType, Transformation transformation, Provider provider,
    byte[] iv) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw new IllegalArgumentException("key size must be 16 or 32 byte: input %d".formatted(key.length));
    }
    return AesCryptoAdapter.builder()
      .secretKeySpec(new SecretKeySpec(key, transformationType.getCode()))
      .ivParameterSpec(new IvParameterSpec(iv))
      .transformation(transformation)
      .provider(provider)
      .build();
  }

  public static AesCrypto aes(byte[] key, Transformation transformation) {
    return aes(key, ALGORITHM_TYPE, transformation, AES_DEFAULT_PROVIDER, AES_DEFAULT_IV);
  }

  public static AesCrypto aes(byte[] key, Transformation transformation, Provider provider) {
    return aes(key, ALGORITHM_TYPE, transformation, provider, AES_DEFAULT_IV);
  }

  public static AesCrypto aes(byte[] key, Transformation transformation, Provider provider, byte[] iv) {
    return aes(key, ALGORITHM_TYPE, transformation, provider, iv);
  }

  public static AesCrypto aes(byte[] key) {
    return aes(key, ALGORITHM_TYPE, AES_DEFAULT_TRANSFORMATION, AES_DEFAULT_PROVIDER, AES_DEFAULT_IV);
  }

  public static AesCrypto aes(String key) {
    return aes(key.getBytes(CHARSET), ALGORITHM_TYPE, AES_DEFAULT_TRANSFORMATION, AES_DEFAULT_PROVIDER, AES_DEFAULT_IV);
  }

  public static AesCrypto aes128() {
    return aes(AES_DEFAULT_KEY_128BIT.getBytes(CHARSET), ALGORITHM_TYPE, AES_DEFAULT_TRANSFORMATION,
      AES_DEFAULT_PROVIDER, AES_DEFAULT_IV);
  }

  public static AesCrypto aes192() {
    return aes(AES_DEFAULT_KEY_192BIT.getBytes(CHARSET), ALGORITHM_TYPE, AES_DEFAULT_TRANSFORMATION,
      AES_DEFAULT_PROVIDER, AES_DEFAULT_IV);
  }

  public static AesCrypto aes256() {
    return aes(AES_DEFAULT_KEY_256BIT.getBytes(CHARSET), ALGORITHM_TYPE, AES_DEFAULT_TRANSFORMATION,
      AES_DEFAULT_PROVIDER, AES_DEFAULT_IV);
  }

  public static AesCrypto empty() {
    return new AesCrypto() {
      @Override
      public byte[] encrypt(byte[] plainText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public byte[] encrypt(String plainText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public String encryptToString(byte[] plainText) throws CryptoException {
        return null;
      }

      @Override
      public String encryptToString(String plainText) throws CryptoException {
        return null;
      }

      @Override
      public byte[] decrypt(byte[] cipherText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public byte[] decrypt(String cipherText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public String decryptToString(byte[] cipherText) throws CryptoException {
        return null;
      }

      @Override
      public String decryptToString(String cipherText) throws CryptoException {
        return null;
      }
    };
  }
}
