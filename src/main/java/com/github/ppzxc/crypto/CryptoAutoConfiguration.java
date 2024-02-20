package com.github.ppzxc.crypto;

import java.security.KeyPair;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoAutoConfiguration {

  @ConditionalOnMissingBean
  @Bean
  public KeyPair keyPair(CryptoProperties cryptoProperties) {
    return RSAKeyFactory.generate(cryptoProperties.getRsa().getPublicKey(),
      cryptoProperties.getRsa().getPrivateKey());
  }

  @ConditionalOnMissingBean
  @Bean
  public RSACrypto crypto(KeyPair keyPair) {
    return RSACryptoAdapter.builder()
      .publicKey(keyPair.getPublic())
      .privateKey(keyPair.getPrivate())
      .build();
  }
}
