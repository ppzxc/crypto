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
  public static final String DEFAULT_AES_128_SYMMETRIC_KEY = "nanoitSecretKeys";
  public static final String DEFAULT_AES_192_SYMMETRIC_KEY = "nanoitSecretKeysNanoitSe";
  public static final String DEFAULT_AES_256_SYMMETRIC_KEY = "nanoitSecretKeysNanoitSecretKeys";
  public static final String DEFAULT_AES_IV_PARAMETER = "nanoitDefaultIvs";
  private static final byte[] DEFAULT_AES_IV_PARAMETER_BYTES = DEFAULT_AES_IV_PARAMETER.getBytes(CHARSET);

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

  public static Crypto aes(byte[] key, Transformation transformation) {
    return aes(key, transformation.getTransformationType(), transformation, AES_DEFAULT_CRYPTO_PROVIDER,
      DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  public static Crypto aes(byte[] key, Transformation transformation, CryptoProvider cryptoProvider) {
    return aes(key, transformation.getTransformationType(), transformation, cryptoProvider,
      DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  public static Crypto aes(byte[] key, Transformation transformation, CryptoProvider cryptoProvider, byte[] iv) {
    return aes(key, transformation.getTransformationType(), transformation, cryptoProvider, iv);
  }

  public static Crypto aes(byte[] key) {
    return aes(key, DEFAULT_AES_TRANSFORMATION.getTransformationType(), DEFAULT_AES_TRANSFORMATION,
      AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  public static Crypto aes(String key) {
    return aes(key.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(), DEFAULT_AES_TRANSFORMATION,
      AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  public static Crypto aes128() {
    return aes(DEFAULT_AES_128_SYMMETRIC_KEY.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(),
      DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  public static Crypto aes192() {
    return aes(DEFAULT_AES_192_SYMMETRIC_KEY.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(),
      DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  public static Crypto aes256() {
    return aes(DEFAULT_AES_256_SYMMETRIC_KEY.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(),
      DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
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
