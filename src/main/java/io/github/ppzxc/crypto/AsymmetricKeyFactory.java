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

public final class AsymmetricKeyFactory {

  public static final CryptoProvider CRYPTO_PROVIDER = CryptoProvider.BOUNCY_CASTLE;
  public static final int DEFAULT_KEY_SIZE = 2048;
  public static final String DEFAULT_PUBLIC_KEY_COMMENT = "PUBLIC KEY";
  public static final String DEFAULT_PRIVATE_RSA_KEY_COMMENT = "RSA PRIVATE KEY";

  private AsymmetricKeyFactory() {
  }

  public static KeyPair generate(AsymmetricKey.Type type, CryptoProvider cryptoProvider, int keySize)
    throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(type.name(), cryptoProvider.getCode());
    generator.initialize(keySize, Constants.SECURE_RANDOM);
    return generator.generateKeyPair();
  }

  public static KeyPair generate(AsymmetricKey asymmetricKey) throws CryptoException {
    return new KeyPair(
      toPublicKey(asymmetricKey.getType(), asymmetricKey.getPublicKey(), X509EncodedKeySpec::new),
      toPrivateKey(asymmetricKey.getType(), asymmetricKey.getPrivateKey(), PKCS8EncodedKeySpec::new));
  }

  public static AsymmetricKey generate(AsymmetricKey.Type type)
    throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
    return toAsymmetricKey(type, generateRsa());
  }

  public static KeyPair generateRsa() throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(AsymmetricKey.Type.RSA, CRYPTO_PROVIDER, DEFAULT_KEY_SIZE);
  }

  public static KeyPair generateRsa(int length) throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(AsymmetricKey.Type.RSA, CRYPTO_PROVIDER, length);
  }

  public static PublicKey toPublicKey(AsymmetricKey.Type type, String publicKey,
    Function<byte[], EncodedKeySpec> encodedKeySpec) throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(publicKey))) {
      return KeyFactory.getInstance(type.name())
        .generatePublic(encodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }
  }

  public static PrivateKey toPrivateKey(AsymmetricKey.Type type, String privateKey,
    Function<byte[], EncodedKeySpec> encodedKeySpec) throws CryptoException {
    try (PemReader pemReader = new PemReader(new StringReader(privateKey))) {
      return KeyFactory.getInstance(type.name())
        .generatePrivate(encodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new CryptoException(e);
    }
  }

  public static AsymmetricKey toAsymmetricKey(AsymmetricKey.Type type, KeyPair keyPair)
    throws IOException {
    return AsymmetricKey.of(type, writeToString(DEFAULT_PUBLIC_KEY_COMMENT, keyPair.getPublic().getEncoded()),
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
