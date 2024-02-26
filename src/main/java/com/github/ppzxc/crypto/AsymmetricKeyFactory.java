package com.github.ppzxc.crypto;

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
import java.security.Security;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.function.Function;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

public final class AsymmetricKeyFactory {

  public static final CryptoProvider CRYPTO_PROVIDER = CryptoProvider.BOUNCY_CASTLE;
  public static final int DEFAULT_KEY_SIZE = 2048;
  public static final String DEFAULT_PUBLIC_KEY_COMMENT = "PUBLIC KEY";
  public static final String DEFAULT_PRIVATE_RSA_KEY_COMMENT = "RSA PRIVATE KEY";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private AsymmetricKeyFactory() {
  }

  /**
   * 표준 key size. DiffieHellman (1024, 2048, 4096). DSA (1024, 2048). RSA (1024, 2048, 4096).
   */
  public static KeyPair generate(AsymmetricKeyType asymmetricKeyType, CryptoProvider cryptoProvider, int keySize)
    throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(asymmetricKeyType.name(), cryptoProvider.getCode());
    generator.initialize(keySize, Constants.SECURE_RANDOM);
    return generator.generateKeyPair();
  }

  public static KeyPair generate(AsymmetricKey asymmetricKey) {
    return new KeyPair(
      toPublicKey(asymmetricKey.getAsymmetricKeyType(), asymmetricKey.getPublicKey(), X509EncodedKeySpec::new),
      toPrivateKey(asymmetricKey.getAsymmetricKeyType(), asymmetricKey.getPrivateKey(), PKCS8EncodedKeySpec::new));
  }

  public static AsymmetricKey generate(AsymmetricKeyType asymmetricKeyType)
    throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
    return toAsymmetricKey(asymmetricKeyType, generateRsa());
  }

  public static KeyPair generateRsa() throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(AsymmetricKeyType.RSA, CRYPTO_PROVIDER, DEFAULT_KEY_SIZE);
  }

  public static KeyPair generateRsa(int length) throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(AsymmetricKeyType.RSA, CRYPTO_PROVIDER, length);
  }

  public static PublicKey toPublicKey(AsymmetricKeyType asymmetricKeyType, String publicKey,
    Function<byte[], EncodedKeySpec> encodedKeySpec) {
    try (PemReader pemReader = new PemReader(new StringReader(publicKey))) {
      return KeyFactory.getInstance(asymmetricKeyType.name())
        .generatePublic(encodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static PrivateKey toPrivateKey(AsymmetricKeyType asymmetricKeyType, String privateKey,
    Function<byte[], EncodedKeySpec> EncodedKeySpec) {
    try (PemReader pemReader = new PemReader(new StringReader(privateKey))) {
      return KeyFactory.getInstance(asymmetricKeyType.name())
        .generatePrivate(EncodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

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
