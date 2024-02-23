package com.github.ppzxc.crypto;

import lombok.Builder;
import lombok.NonNull;

@Builder
public record SymmetricKey(@NonNull String key) {

  public SymmetricKey {
    if (key.isBlank()) {
      throw new IllegalArgumentException("'SymmetricKey' require not blank");
    }
  }
}