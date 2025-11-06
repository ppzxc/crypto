package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class CryptoFactory {

  public static final Charset CHARSET = StandardCharsets.UTF_8;
  public static final CryptoProvider AES_DEFAULT_CRYPTO_PROVIDER = CryptoProvider.BOUNCY_CASTLE;
  public static final Transformation DEFAULT_AES_TRANSFORMATION = Transformation.AES_CBC_PKCS7PADDING;

  private CryptoFactory() {
  }

  public static Crypto aes(byte[] key, TransformationType transformationType, Transformation transformation,
    CryptoProvider cryptoProvider, byte[] iv) {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw new IllegalArgumentException(String.format("key size must be 16 or 32 byte: input %d", key.length));
    }
    if (transformation.getTransformationMode() == TransformationMode.ELECTRONIC_CODE_BLOCK) {
      return AesCrypto.builder()
        .secretKeySpec(new SecretKeySpec(key, transformationType.getCode()))
        .transformation(transformation)
        .cryptoProvider(cryptoProvider)
        .build();
    } else {
      return AesCrypto.builder()
        .secretKeySpec(new SecretKeySpec(key, transformationType.getCode()))
        .ivParameterSpec(new IvParameterSpec(iv))
        .transformation(transformation)
        .cryptoProvider(cryptoProvider)
        .build();
    }
  }

  public static Crypto aes(byte[] key, Transformation transformation, byte[] iv) {
    return aes(key, transformation.getTransformationType(), transformation, AES_DEFAULT_CRYPTO_PROVIDER, iv);
  }

  public static Crypto aes(byte[] key, Transformation transformation, CryptoProvider cryptoProvider, byte[] iv) {
    return aes(key, transformation.getTransformationType(), transformation, cryptoProvider, iv);
  }

  public static Crypto aes(byte[] key, byte[] iv) {
    return aes(key, DEFAULT_AES_TRANSFORMATION.getTransformationType(), DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, iv);
  }

  public static Crypto rsa(PublicKey publicKey, PrivateKey privateKey) {
    return RsaCrypto.builder()
      .publicKey(publicKey)
      .privateKey(privateKey)
      .build();
  }

  public static Crypto rsa(PublicKey publicKey) {
    return RsaPublicCrypto.builder()
      .publicKey(publicKey)
      .build();
  }

  public static Crypto rsa(KeyPair keyPair) {
    return rsa(keyPair.getPublic(), keyPair.getPrivate());
  }
}
