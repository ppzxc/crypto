package io.github.ppzxc.crypto;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * The type Symmetric key.
 */
public class SymmetricKey {

  /**
   * The constant CHARSET.
   */
  public static final Charset CHARSET = StandardCharsets.UTF_8;
  private final String key;

  /**
   * Instantiates a new Symmetric key.
   *
   * @param key the key
   */
  public SymmetricKey(String key) {
    this.key = key;
    if (key == null || key.trim().isEmpty()) {
      throw new IllegalArgumentException("'SymmetricKey' require not blank");
    }
  }

  /**
   * Gets key.
   *
   * @return the key
   */
  public String getKey() {
    return key;
  }

  /**
   * Get key byte array byte [ ].
   *
   * @param charset the charset
   * @return the byte [ ]
   */
  public byte[] getKeyByteArray(Charset charset) {
    return key.getBytes(charset);
  }

  /**
   * Get key byte array byte [ ].
   *
   * @return the byte [ ]
   */
  public byte[] getKeyByteArray() {
    return getKeyByteArray(CHARSET);
  }
}