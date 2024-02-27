package io.github.ppzxc.crypto;

import java.nio.charset.StandardCharsets;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

@State(Scope.Benchmark)
public class Aes128CbcPkcs7PaddingExecutionPlan {

  //  @Param({"100", "200", "300", "500", "1000"})
  @Param({"100"})
  public int iterations;

  public Crypto crypto;

  public SymmetricKey symmetricKey = SymmetricKeyFactory.bit128();
  public TransformationType transformationType = TransformationType.ADVANCED_ENCRYPTION_STANDARD;
  public Transformation transformation = Transformation.AES_CBC_PKCS5PADDING;
  public CryptoProvider cryptoProvider = CryptoProvider.BOUNCY_CASTLE;
  public byte[] iv = CryptoFactory.DEFAULT_AES_IV_PARAMETER_BYTES;

  public byte[] payload1024 = RandomBytes.giveMeOne(1024);

  @Setup(Level.Invocation)
  public void setUp() throws RuntimeException {
    crypto = CryptoFactory.aes(symmetricKey.getKey().getBytes(StandardCharsets.UTF_8), transformationType,
      transformation, cryptoProvider, iv);
  }
}
