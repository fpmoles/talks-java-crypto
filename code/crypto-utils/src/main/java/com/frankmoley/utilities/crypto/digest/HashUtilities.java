package com.frankmoley.utilities.crypto.digest;

import com.frankmoley.utilities.crypto.exception.ProviderBasedException;
import org.mindrot.jbcrypt.BCrypt;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;

/**
 * @author Frank P. Moley III.
 */
public class HashUtilities {

    private static HashUtilities instance;

    private static final String SHA2_ALGORITHM = "SHA-256";

    private HashUtilities(){
        super();
    }

    /**
     * Gets a singleton instance of the HashUtilities
     * @return the singleton instance
     */
    public static HashUtilities getInstance(){
        if(null==instance){
            synchronized (HashUtilities.class){
                if(null==instance) {
                    instance = new HashUtilities();
                }
            }
        }
        return instance;
    }

    /**
     * Creates a Hash of an byte array using the SHA-256 algorithm
     * @param bytesToHash the byte array to hash
     * @param salt the salt to add to the hash
     * @return the hash that was generated
     */
    public byte[] createSHA256Hash(byte[] bytesToHash, byte[] salt){
        try{
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byteStream.write(salt);
            byteStream.write(bytesToHash);
            byte[] valueToHash = byteStream.toByteArray();
            MessageDigest messageDigest = MessageDigest.getInstance(SHA2_ALGORITHM);
            return messageDigest.digest(valueToHash);
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when performing hash operation using algorithm: " + SHA2_ALGORITHM, e);
        }
    }

    /**
     * Creates a BCrypt hash of a password using 12 rounds of hashing
     * @param password the password to hash
     * @return the BCrypt hash
     */
    public String hashPassword(String password){
        int rounds = 12;
        return BCrypt.hashpw(password, BCrypt.gensalt(rounds));
    }

    /**
     * Verifies a password against a given hash to determine if the hash originated from the same password
     * @param password the password to check against the hash
     * @param hashedPassword the current hash
     * @return boolean indication if the password would generate the given hash
     */
    public boolean verifyPassord(String password, String hashedPassword){
        return BCrypt.checkpw(password, hashedPassword);
    }

}
