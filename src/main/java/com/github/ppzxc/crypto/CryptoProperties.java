package com.github.ppzxc.crypto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "gateway.cipher")
public class CryptoProperties {

  private Rsa rsa = new Rsa();

  @Getter
  @Setter
  public static class Rsa {

    private int size = 2048;
    private String publicKey = """
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmYy6QefKxfEBF2n2vwNn
      QphSthqElc4iUiLGCAbBA0ctK7Lh44uGR49j+hp0Ouyo1vrnvGirV2zLxw7ciwRf
      wZnaLrnjHU6EFwZJio6JFqp2ix8M5+MxO2gbq1nhGmdJkrcN7NTbDJgz5lUO3qLJ
      JYdGRtvm5+2ZUe/TPGb4KWJUwL/FTQf8VUqgelLSNt+feCxwoiYAVduay58nNPQx
      HMdbCxdrNZz2Rb0Kc171swstOialkCsIRyagl/dAiW+Obykv+wz4wyh561l6GvI4
      +CbvbXpFNuqXQYi9p2hGRba5Z7kAH2dWPoNI4kxMsDrO4WdHKpsLh1Z95S1232Is
      +wIDAQAB
      -----END PUBLIC KEY-----
      """;
    private String privateKey = """
      -----BEGIN RSA PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZjLpB58rF8QEX
      afa/A2dCmFK2GoSVziJSIsYIBsEDRy0rsuHji4ZHj2P6GnQ67KjW+ue8aKtXbMvH
      DtyLBF/BmdouueMdToQXBkmKjokWqnaLHwzn4zE7aBurWeEaZ0mStw3s1NsMmDPm
      VQ7eosklh0ZG2+bn7ZlR79M8ZvgpYlTAv8VNB/xVSqB6UtI23594LHCiJgBV25rL
      nyc09DEcx1sLF2s1nPZFvQpzXvWzCy06JqWQKwhHJqCX90CJb45vKS/7DPjDKHnr
      WXoa8jj4Ju9tekU26pdBiL2naEZFtrlnuQAfZ1Y+g0jiTEywOs7hZ0cqmwuHVn3l
      LXbfYiz7AgMBAAECggEAObdWA5PW+lQ+rshbwSzMUZHj9SM+lvimme0MNtQjFNJa
      PkS898ToMlnJoKb07XkrdbNWC9HkJbZ1WltRtsdsHt9vzYR9w/RRXj40wmoVSXnF
      mUGQnlEdnlDhpaThIgWU+BrqlwzjUXace4WZU0IpDXwthFEAGEmNCel1owypVxRT
      0s4deAxtj24HpZBXbLByo9l4BX36/GIG16DyBS2R5fZ9j3axtN0cYpQejLAUOukE
      mD8Zg8jZEZPkbqX499I7Smu2WGPsYM8pGNrY3TcjBH5L/6rUkOTOwsNTsMrJae/I
      olsiu8WONK+AkQYFLI/cnlbLuPNq+N8BWAo10mh6AQKBgQDN+VR/Ix/WbBBXcJr5
      YIh2ydoV5OhnJlbQKcsVi2uj8w6rxHwzsGHyHEo2ui6LcdthkGVMOQJSri8vELXA
      CnkDmf5j3iYsOwbBMUOGPmUPkxq5vYqZbJE2xxLwhfjsJip9uO1mhjUTGBgH9F44
      S9lA8T0ktHYRbom80AoE3DXxewKBgQC+19wr5AKm8PwGcwhASmwIhko/+thfu+1C
      6hOm2byFj490H8ymiKwXLsjssp1gpFs4FOFxQQUeKKi7uP0K4T1NHgwXSeA+cVtg
      zyleNsv4KRzqSEFvGmqsSHkZ7WLbyfIXSb6ZNwIlnPRquJy6WTrc1Uvt4UE5PIyM
      ogosUPcagQKBgQC27jKSO8LB7/XPgs3Qn2Bzh7At88BIJC/D7upT9yAhWvPzr6zT
      R1ql6WQsGMzPwc4iZ1jgCl26ysJTHZcduO9jOHhLf/gNHltQZ41eA7pDy9VXkzQu
      MNMDgGicv4+lQ/xG7l/Bx34JuENXhTvM6ehImjhAihm2P6MK0wWi7WTnUwKBgDUO
      dhuNrF8VKDvyxxx4lEhabVIUPwt+h5vOz9/XMN5A5zT1kkPKQ22+iAWmMrKnfuS8
      iWCfHvkffKmT6GWZ8Rz7eYkP9NPnV+w2K94RhetcIrnPlMF6qqVzEJfws0c/gZqP
      2flmnaYvWJRC9u+n1wGGGzHrKeLrvndqpUFk0Q4BAoGBAMn5RWgkAKxn1cakVnxs
      nR1zdg5ICMADez8NaTxmvF0muwEzhWKSqbDGp+SlpmRaw6UcgTsYBeum86QiP3IE
      2VWaQyFy2ey8J6tThPGqhLHqzHKOJHJ6alFYtcFtTd5Gfp7ZvzUYuuJIHTSsojJ4
      CsIERbJzwbGWBXlpDxM6gSsF
      -----END RSA PRIVATE KEY-----
      """;
  }
}
