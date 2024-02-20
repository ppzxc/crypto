package com.github.ppzxc.crypto;

public interface Crypto {

  byte[] encrypt(byte[] plainText) throws CryptoException;

  byte[] encrypt(String plainText) throws CryptoException;

  String encryptToString(byte[] plainText) throws CryptoException;

  String encryptToString(String plainText) throws CryptoException;

  byte[] decrypt(byte[] cipherText) throws CryptoException;

  byte[] decrypt(String cipherText) throws CryptoException;

  String decryptToString(byte[] cipherText) throws CryptoException;

  String decryptToString(String cipherText) throws CryptoException;
}
