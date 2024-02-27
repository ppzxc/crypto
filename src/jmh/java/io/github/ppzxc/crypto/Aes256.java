package io.github.ppzxc.crypto;

import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.infra.Blackhole;

public class Aes256 {

  @Threads(Threads.MAX)
  @Benchmark
  @BenchmarkMode({Mode.AverageTime, Mode.Throughput})
  @OutputTimeUnit(TimeUnit.MILLISECONDS)
  @Fork(value = 1, warmups = 1)
  public void aes256_1024byte_payload(Blackhole blackhole, Aes256CbcPkcs7PaddingExecutionPlan plan) {
    for (int i = plan.iterations; i > 0; i--) {
    try {
      blackhole.consume(plan.crypto.encrypt(plan.payload1024));
    } catch (CryptoException e) {
      throw new RuntimeException(e);
    }
    }
  }
}
