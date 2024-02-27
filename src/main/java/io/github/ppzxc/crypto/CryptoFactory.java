package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The type Crypto factory.
 */
public final class CryptoFactory {

  /**
   * The constant CHARSET.
   */
  public static final Charset CHARSET = StandardCharsets.UTF_8;
  /**
   * The constant AES_DEFAULT_CRYPTO_PROVIDER.
   */
  public static final CryptoProvider AES_DEFAULT_CRYPTO_PROVIDER = CryptoProvider.BOUNCY_CASTLE;
  /**
   * The constant DEFAULT_AES_TRANSFORMATION.
   */
  public static final Transformation DEFAULT_AES_TRANSFORMATION = Transformation.AES_CBC_PKCS5PADDING;
  /**
   * The constant DEFAULT_AES_128_SYMMETRIC_KEY.
   */
  public static final String DEFAULT_AES_128_SYMMETRIC_KEY = "nanoitSecretKeys";
  /**
   * The constant DEFAULT_AES_192_SYMMETRIC_KEY.
   */
  public static final String DEFAULT_AES_192_SYMMETRIC_KEY = "nanoitSecretKeysNanoitSe";
  /**
   * The constant DEFAULT_AES_256_SYMMETRIC_KEY.
   */
  public static final String DEFAULT_AES_256_SYMMETRIC_KEY = "nanoitSecretKeysNanoitSecretKeys";
  /**
   * The constant DEFAULT_AES_IV_PARAMETER.
   */
  public static final String DEFAULT_AES_IV_PARAMETER = "nanoitDefaultIvs";
  /**
   * The constant DEFAULT_AES_IV_PARAMETER_BYTES.
   */
  public static final byte[] DEFAULT_AES_IV_PARAMETER_BYTES = DEFAULT_AES_IV_PARAMETER.getBytes(CHARSET);

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private CryptoFactory() {
  }

  /**
   * Aes crypto.
   *
   * @param key                the key
   * @param transformationType the transformation type
   * @param transformation     the transformation
   * @param cryptoProvider     the crypto provider
   * @param iv                 the iv
   * @return the crypto
   */
  public static Crypto aes(byte[] key, TransformationType transformationType, Transformation transformation,
    CryptoProvider cryptoProvider,
    byte[] iv) {
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

  /**
   * Aes crypto.
   *
   * @param key            the key
   * @param transformation the transformation
   * @return the crypto
   */
  public static Crypto aes(byte[] key, Transformation transformation) {
    return aes(key, transformation.getTransformationType(), transformation, AES_DEFAULT_CRYPTO_PROVIDER,
      DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Aes crypto.
   *
   * @param key            the key
   * @param transformation the transformation
   * @param cryptoProvider the crypto provider
   * @return the crypto
   */
  public static Crypto aes(byte[] key, Transformation transformation, CryptoProvider cryptoProvider) {
    return aes(key, transformation.getTransformationType(), transformation, cryptoProvider,
      DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Aes crypto.
   *
   * @param key            the key
   * @param transformation the transformation
   * @param cryptoProvider the crypto provider
   * @param iv             the iv
   * @return the crypto
   */
  public static Crypto aes(byte[] key, Transformation transformation, CryptoProvider cryptoProvider, byte[] iv) {
    return aes(key, transformation.getTransformationType(), transformation, cryptoProvider, iv);
  }

  /**
   * Aes crypto.
   *
   * @param key the key
   * @return the crypto
   */
  public static Crypto aes(byte[] key) {
    return aes(key, DEFAULT_AES_TRANSFORMATION.getTransformationType(), DEFAULT_AES_TRANSFORMATION,
      AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Aes crypto.
   *
   * @param key the key
   * @return the crypto
   */
  public static Crypto aes(String key) {
    return aes(key.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(), DEFAULT_AES_TRANSFORMATION,
      AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Aes 128 crypto.
   *
   * @return the crypto
   */
  public static Crypto aes128() {
    return aes(DEFAULT_AES_128_SYMMETRIC_KEY.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(),
      DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Aes 192 crypto.
   *
   * @return the crypto
   */
  public static Crypto aes192() {
    return aes(DEFAULT_AES_192_SYMMETRIC_KEY.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(),
      DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Aes 256 crypto.
   *
   * @return the crypto
   */
  public static Crypto aes256() {
    return aes(DEFAULT_AES_256_SYMMETRIC_KEY.getBytes(CHARSET), DEFAULT_AES_TRANSFORMATION.getTransformationType(),
      DEFAULT_AES_TRANSFORMATION, AES_DEFAULT_CRYPTO_PROVIDER, DEFAULT_AES_IV_PARAMETER_BYTES);
  }

  /**
   * Rsa crypto.
   *
   * @param publicKey  the public key
   * @param privateKey the private key
   * @return the crypto
   */
  public static Crypto rsa(PublicKey publicKey, PrivateKey privateKey) {
    return RsaCrypto.builder()
      .publicKey(publicKey)
      .privateKey(privateKey)
      .build();
  }
}
