package com.github.ppzxc.crypto;

import lombok.Builder;

@Builder
public record RSAKey(String publicKey, String privateKey) {

}