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
import java.security.SecureRandom;
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

public final class RSAKeyFactory {

  public static final Transformation TRANSFORMATION = Transformation.RSA;
  public static final Provider PROVIDER = Provider.BOUNCY_CASTLE;
  public static final int DEFAULT_KEY_SIZE = 2048;
  public static final String DEFAULT_PUBLIC_KEY_COMMENT = "PUBLIC KEY";
  public static final String DEFAULT_PRIVATE_KEY_COMMENT = "RSA PRIVATE KEY";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private RSAKeyFactory() {
  }

  public static KeyPair generate(Transformation transformation, Provider provider, int keySize)
    throws NoSuchAlgorithmException, NoSuchProviderException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(transformation.getCode(), provider.getCode());
    generator.initialize(keySize, new SecureRandom());
    return generator.generateKeyPair();
  }

  public static KeyPair generate() throws NoSuchAlgorithmException, NoSuchProviderException {
    return generate(TRANSFORMATION, PROVIDER, DEFAULT_KEY_SIZE);
  }

  public static RSAKey generateToString(KeyPair keyPair) throws IOException {
    return RSAKey.builder()
      .publicKey(writeToString(DEFAULT_PUBLIC_KEY_COMMENT, keyPair.getPublic().getEncoded()))
      .privateKey(writeToString(DEFAULT_PRIVATE_KEY_COMMENT, keyPair.getPrivate().getEncoded()))
      .build();
  }

  public static KeyPair generate(RSAKey rsaKey) {
    return generate(rsaKey.publicKey(), rsaKey.privateKey());
  }

  public static KeyPair generate(String publicKey, String privateKey) {
    return new KeyPair(toPublicKey(publicKey), toPrivateKey(privateKey));
  }

  public static RSAKey generateToString() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
    return generateToString(generate());
  }

  public static PublicKey toPublicKey(String publicKey, Function<byte[], EncodedKeySpec> encodedKeySpec) {
    try (PemReader pemReader = new PemReader(new StringReader(publicKey))) {
      return KeyFactory.getInstance(TRANSFORMATION.getCode())
        .generatePublic(encodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static PublicKey toPublicKey(String publicKey) {
    return toPublicKey(publicKey, X509EncodedKeySpec::new);
  }

  public static PrivateKey toPrivateKey(String privateKey, Function<byte[], EncodedKeySpec> EncodedKeySpec) {
    try (PemReader pemReader = new PemReader(new StringReader(privateKey))) {
      return KeyFactory.getInstance(TRANSFORMATION.getCode())
        .generatePrivate(EncodedKeySpec.apply(pemReader.readPemObject().getContent()));
    } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static PrivateKey toPrivateKey(String privateKey) {
    return toPrivateKey(privateKey, PKCS8EncodedKeySpec::new);
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
