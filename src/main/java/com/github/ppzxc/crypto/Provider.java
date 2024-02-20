package com.github.ppzxc.crypto;

import lombok.Getter;

@Getter
public enum Provider {
  BOUNCY_CASTLE("BC");

  private final String code;

  Provider(String code) {
    this.code = code;
  }
}
