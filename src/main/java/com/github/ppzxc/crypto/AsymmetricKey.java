package com.github.ppzxc.crypto;

import lombok.Builder;
import lombok.NonNull;

@Builder
public record AsymmetricKey(
  @NonNull
  String publicKey,
  @NonNull
  String privateKey) {

  public AsymmetricKey {
    if (publicKey.isBlank()) {
      throw new IllegalArgumentException("'PublicKey' require not blank");
    }
    if (privateKey.isBlank()) {
      throw new IllegalArgumentException("'PrivateKey' require not blank");
    }
  }
}