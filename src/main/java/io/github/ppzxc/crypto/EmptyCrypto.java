package io.github.ppzxc.crypto;

public final class EmptyCrypto {

  private EmptyCrypto() {
  }

  public static Crypto create() {
    return new Crypto() {
      @Override
      public byte[] encrypt(byte[] plainText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public byte[] encrypt(String plainText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public String encryptToString(byte[] plainText) throws CryptoException {
        return null;
      }

      @Override
      public String encryptToString(String plainText) throws CryptoException {
        return null;
      }

      @Override
      public byte[] decrypt(byte[] cipherText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public byte[] decrypt(String cipherText) throws CryptoException {
        return new byte[0];
      }

      @Override
      public String decryptToString(byte[] cipherText) throws CryptoException {
        return null;
      }

      @Override
      public String decryptToString(String cipherText) throws CryptoException {
        return null;
      }
    };
  }
}
