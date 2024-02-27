package io.github.ppzxc.crypto;

/**
 * The interface Crypto.
 */
public interface Crypto {

  /**
   * Encrypt for byte[] to byte[].
   *
   * @param plainText the plain text
   * @return the byte[]
   * @throws CryptoException the crypto exception
   */
  byte[] encrypt(byte[] plainText) throws CryptoException;

  /**
   * Encrypt for string to byte[].
   *
   * @param plainText the plain text
   * @return the byte[]
   * @throws CryptoException the crypto exception
   */
  byte[] encrypt(String plainText) throws CryptoException;

  /**
   * Encrypt for byte[] to string.
   *
   * @param plainText the plain text
   * @return the string
   * @throws CryptoException the crypto exception
   */
  String encryptToString(byte[] plainText) throws CryptoException;

  /**
   * Encrypt for string to string.
   *
   * @param plainText the plain text
   * @return the string
   * @throws CryptoException the crypto exception
   */
  String encryptToString(String plainText) throws CryptoException;

  /**
   * Decrypt for byte[] to byte[].
   *
   * @param cipherText the cipher text
   * @return the byte[]
   * @throws CryptoException the crypto exception
   */
  byte[] decrypt(byte[] cipherText) throws CryptoException;

  /**
   * Decrypt for string to byte[].
   *
   * @param cipherText request decryption cipher text.
   * @return plaintext. byte[]
   * @throws CryptoException decryption failed.
   */
  byte[] decrypt(String cipherText) throws CryptoException;

  /**
   * Decrypt for byte[] to string.
   *
   * @param cipherText the cipher text
   * @return the string
   * @throws CryptoException the crypto exception
   */
  String decryptToString(byte[] cipherText) throws CryptoException;

  /**
   * Decrypt for string to string.
   *
   * @param cipherText the cipher text
   * @return the string
   * @throws CryptoException the crypto exception
   */
  String decryptToString(String cipherText) throws CryptoException;
}
