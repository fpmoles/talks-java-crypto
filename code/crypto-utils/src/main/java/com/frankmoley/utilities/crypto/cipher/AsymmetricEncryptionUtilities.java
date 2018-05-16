package com.frankmoley.utilities.crypto.cipher;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.frankmoley.utilities.crypto.exception.ProviderBasedException;

/**
 * @author Frank P. Moley III.
 */
public class AsymmetricEncryptionUtilities {

    private static AsymmetricEncryptionUtilities instance;

    private static final String RSA = "RSA";

    private AsymmetricEncryptionUtilities(){
        super();
    }

    /**
     * Gets a singleton instance of the AsymmetricEncryptionUtilities
     * @return the singleton instance
     */
    public static AsymmetricEncryptionUtilities getInstance(){
        if(null==instance){
            synchronized (AsymmetricEncryptionUtilities.class){
                if(null==instance) {
                    instance = new AsymmetricEncryptionUtilities();
                }
            }
        }
        return instance;
    }

    /**
     * Generates an RSA 4096 KeyPair
     * @return the KeyPair
     */
    public KeyPair generateRSAKeyPair(){
        int keySize = 4096;
        try {
            SecureRandom secureRandom = new SecureRandom();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(keySize, secureRandom);
            return keyPairGenerator.generateKeyPair();
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when creating key with algorithm:  " + RSA, e);
        }
    }

    /**
     * Performs RSA encryption using the private key
     * @param privateKey the private key from the KeyPair to be used for the encryption operation
     * @param plainText the String to encrypt
     * @return the cipher text bytes
     */
    public byte[] performRSAEncryption(String plainText, PrivateKey privateKey){
        try {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(plainText.getBytes());
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when performing encryption operation using algorithm: " + RSA, e);
        }
    }

    /**
     * Performs RSA decryption using the public key
     * @param publicKey the public key from the KeyPair to be used for the encryption operation
     * @param cipherText the bytes to decrypt
     * @return the unencrypted plain text
     */
    public String performRSADecryption(byte[] cipherText, PublicKey publicKey){
        try {
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] result = cipher.doFinal(cipherText);
            return new String(result);
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when performing decryption operation using algorithm: " + RSA, e);
        }
    }

}
