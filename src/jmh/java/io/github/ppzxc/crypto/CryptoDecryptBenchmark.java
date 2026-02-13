package io.github.ppzxc.crypto;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
public class CryptoDecryptBenchmark {

  @Param({"64", "128", "256", "512", "1024", "2048", "4096"})
  private int payloadSize;

  private Crypto aesCrypto;
  private byte[] encryptedPayload;

  @Setup(Level.Trial)
  public void setUp() throws CryptoException {
    CryptoProvider.BOUNCY_CASTLE.addProvider();
    byte[] key = new byte[32]; // AES-256
    byte[] iv = "1234567890123456".getBytes(StandardCharsets.UTF_8);
    aesCrypto = CryptoFactory.aes(key, Transformation.AES_CBC_PKCS7PADDING, CryptoProvider.BOUNCY_CASTLE, iv);
    
    byte[] plainPayload = new byte[payloadSize];
    ThreadLocalRandom.current().nextBytes(plainPayload);
    encryptedPayload = aesCrypto.encrypt(plainPayload);
  }

  @Benchmark
  public byte[] decrypt() throws CryptoException {
    return aesCrypto.decrypt(encryptedPayload);
  }
}
