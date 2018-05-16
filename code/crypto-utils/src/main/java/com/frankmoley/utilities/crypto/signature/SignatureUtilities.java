package com.frankmoley.utilities.crypto.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import com.frankmoley.utilities.crypto.exception.ProviderBasedException;

/**
 * @author Frank P. Moley III.
 */
public class SignatureUtilities {

    private static SignatureUtilities instance;

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";

    private SignatureUtilities(){
        super();
    }

    /**
     * Gets a singleton instance of the SignatureUtilities
     * @return the singleton instance
     */
    public static SignatureUtilities getInstance(){
        if(null == instance){
            synchronized (SignatureUtilities.class){
                if(null==instance){
                    instance = new SignatureUtilities();
                }
            }
        }
        return instance;
    }

    /**
     * Creates a digital signature of the bytes using the private key
     * @param bytesToSign the input bytes to sign
     * @param privateKey the private key to sign the bytes with
     * @return the digital signature
     */
    public byte[] createDigitalSignature(byte[] bytesToSign, PrivateKey privateKey){
        try {
            Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
            signature.initSign(privateKey);
            signature.update(bytesToSign);
            return signature.sign();
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when performing signature operation using algorithm: " + SIGNING_ALGORITHM, e);
        }
    }

    /**
     * Verifies a digital signature against the original bytes and the public key
     * @param originalBytes the original bytes
     * @param signatureToVerify the digital signature
     * @param publicKey the public key
     * @return boolean indication of the validity of the signature
     */
    public boolean verifyDigitalSignature(byte[] originalBytes, byte[]signatureToVerify, PublicKey publicKey){
        try {
            Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(originalBytes);
            return signature.verify(signatureToVerify);
        }catch(Exception e){
            throw new ProviderBasedException("Provider exception when performing verification of signature operation using algorithm: " + SIGNING_ALGORITHM, e);
        }
    }
}
