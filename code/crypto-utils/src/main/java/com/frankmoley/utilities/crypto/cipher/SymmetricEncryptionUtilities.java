package com.frankmoley.utilities.crypto.cipher;

import com.frankmoley.utilities.crypto.exception.ProviderBasedException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class for working with Symmetric ciphers
 * @author Frank P. Moley III.
 */
public class SymmetricEncryptionUtilities {

    private static SymmetricEncryptionUtilities instance;
    private static final String AES = "AES";
    private static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    private SymmetricEncryptionUtilities(){
        super();
    }

    /**
     * Gets a singleton instance of the SymmetricEncryptionUtilities
     * @return the singleton instance
     */
    public static SymmetricEncryptionUtilities getInstance(){
        if(null==instance){
            synchronized (SymmetricEncryptionUtilities.class){
                if(null==instance) {
                    instance = new SymmetricEncryptionUtilities();
                }
            }
        }
        return instance;
    }

    /**
     * Generates a AES 256 bit key
     * @return the SecretKey
     */
    public SecretKey getAesKey(){
        int keySize = 256;
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
            keyGenerator.init(keySize, secureRandom);
            return keyGenerator.generateKey();
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when creating key with algorithm:  " + AES, e);
        }
    }

    /**
     * Creates a 16 byte initialization vector for use with a CBC mode block cipher
     * @return the initialization vector
     */
    public byte[] getInitializationVector(){
        int ivSize = 16;
        byte[] initializationVector = new byte[ivSize];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }

    /**
     * Performs AES encryption using a CBC mode with PKCS5Padding for the blocks
     * @param secretKey the secret key to be used for the encryption operation
     * @param initializationVector the initialization vector for the CBC mode
     * @param plainText the String to encrypt
     * @return the cipher text bytes
     */
    public byte[] performAesEncryption(SecretKey secretKey, byte[] initializationVector, String plainText){
        try {
            Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
            return cipher.doFinal(plainText.getBytes());
        }catch (Exception e) {
            throw new ProviderBasedException("Provider exception when performing encryption operation using algorithm: " + AES_CIPHER_ALGORITHM, e);
        }
    }

    /**
     * Performs AES decryption using a CBC mode with PKCS5Padding for the blocks
     * @param secretKey the secret key to be used for the decryption operation
     * @param initializationVector the initialization vector originally used for the CBC mode
     * @param cipherText the bytes to decrypt
     * @return the plain text string
     */
    public String performAesDecryption(SecretKey secretKey, byte[] initializationVector, byte[] cipherText){
        try{
            Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
            return new String(cipher.doFinal(cipherText));
        }catch (Exception e){
            throw new ProviderBasedException("Provider exception when performing decryption operation using algorithm: " + AES_CIPHER_ALGORITHM, e);
        }
    }


}
