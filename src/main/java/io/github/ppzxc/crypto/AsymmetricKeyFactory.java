package io.github.ppzxc.crypto;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Function;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * The type Asymmetric key factory.
 */
public final class AsymmetricKeyFactory {

  /**
   * The constant CRYPTO_PROVIDER.
   */
  public static final CryptoProvider CRYPTO_PROVIDER = CryptoProvider.BOUNCY_CASTLE;
  /**
   * The constant DEFAULT_KEY_SIZE.
   */
  public static final int DEFAULT_KEY_SIZE = 2048;
  /**
   * The constant DEFAULT_PUBLIC_KEY_COMMENT.
   */
  public static final String DEFAULT_PUBLIC_KEY_COMMENT = "PUBLIC KEY";
  /**
   * The constant DEFAULT_PRIVATE_RSA_KEY_COMMENT.
   */
  public static final String DEFAULT_PRIVATE_RSA_KEY_COMMENT = "RSA PRIVATE KEY";

  private AsymmetricKeyFactory() {
  }

  /**
   * Generate key pair.
   *
   * @param asymmetricKeyType the asymmetric key type
   * @param cryptoProvider    the crypto provider
   * @param keySize           the key size
   * @return the key pair
   * @throws NoSuchAlgorithmException the no such algorithm exception
   * @throws NoSuchProviderException  the no such provider exception
   */
  public static KeyPair generate(AsymmetricKeyType asymmetricKeyType, CryptoProvider cryptoProvider, int keySize)
    throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(asymmetricKeyType.name(), cryptoProvider.getCode());
    generator.initialize(keySize, Constants.SECURE_RANDOM);
    return generator.generateKeyPair();
  }

  /**
   * Generate key pair.
   *
   * @param asymmetricKey the asymmetric key
   * @return the key pair
   * @throws CryptoException the crypto exception
   */
  public static KeyPair generate(AsymmetricKey asymmetricKey) throws CryptoException {
    return new KeyPair(
      toPublicKey(asymmetricKey.getAsymmetricKeyType(), asymmetricKey.getPublicKey(), X509EncodedKeySpec::new),
      toPrivateKey(asymmetricKey.getAsymmetricKeyType(), asymmetricKey.getPrivateKey(), PKCS8EncodedKeySpec::new));
  }

  /**
   * Generate asymmetric key.
   *
   * @param asymmetricKeyType the asymmetric key type
   * @return the asymmetric key
   * @throws NoSuchAlgorithmException the no such algorithm exception
   * @throws NoSuchProviderException  the no such provider exception
   * @throws IOException              the io exception
   */
  public static AsymmetricKey generate(AsymmetricKeyType asymmetricKeyType)
    throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
    return toAsymmetricKey(asymmetricKeyType, generateRsa());
  }

  /**
   * Generate rsa key pair.
   *
   * @return the key pair
   * @throws NoSuchAlgorithmException the no such algorithm exception
   * @throws NoSuchProviderException  the no such provider exception
   */
  public static KeyPair generateRsa() throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(AsymmetricKeyType.RSA, CRYPTO_PROVIDER, DEFAULT_KEY_SIZE);
  }

  /**
   * Generate rsa key pair.
   *
   * @param length the length
   * @return the key pair
   * @throws NoSuchAlgorithmException the no such algorithm exception
   * @throws NoSuchProviderException  the no such provider exception
   */
  public static KeyPair generateRsa(int length) throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(AsymmetricKeyType.RSA, CRYPTO_PROVIDER, length);
  }

  /**
   * To public key public key.
   *
   * @param asymmetricKeyType the asymmetric key type
   * @param publicKey         the public key
   * @param encodedKeySpec    the encoded key spec
   * @return the public key
   * @throws CryptoException the crypto exception
   */
  public static PublicKey toPublicKey(AsymmetricKeyType asymmetricKeyType, String publicKey,
    Function<byte[], EncodedKeySpec> encodedKeySpec) throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(publicKey))) {
      return KeyFactory.getInstance(asymmetricKeyType.name())
        .generatePublic(encodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * To private key private key.
   *
   * @param asymmetricKeyType the asymmetric key type
   * @param privateKey        the private key
   * @param encodedKeySpec    the encoded key spec
   * @return the private key
   * @throws CryptoException the crypto exception
   */
  public static PrivateKey toPrivateKey(AsymmetricKeyType asymmetricKeyType, String privateKey,
    Function<byte[], EncodedKeySpec> encodedKeySpec) throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(privateKey))) {
      return KeyFactory.getInstance(asymmetricKeyType.name())
        .generatePrivate(encodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }
  }

  /**
   * To asymmetric key asymmetric key.
   *
   * @param asymmetricKeyType the asymmetric key type
   * @param keyPair           the key pair
   * @return the asymmetric key
   * @throws IOException the io exception
   */
  public static AsymmetricKey toAsymmetricKey(AsymmetricKeyType asymmetricKeyType, KeyPair keyPair)
    throws IOException {
    return AsymmetricKey.of(asymmetricKeyType,
      writeToString(DEFAULT_PUBLIC_KEY_COMMENT, keyPair.getPublic().getEncoded()),
      writeToString(DEFAULT_PRIVATE_RSA_KEY_COMMENT, keyPair.getPrivate().getEncoded()));
  }

  private static String writeToString(String desc, byte[] key) throws IOException {
    PemObject pemObject = new PemObject(desc, key);
    StringWriter stringWriter = new StringWriter();
    PemWriter pemWriter = new PemWriter(stringWriter);
    pemWriter.writeObject(pemObject);
    pemWriter.close();
    return stringWriter.toString();
  }
}
