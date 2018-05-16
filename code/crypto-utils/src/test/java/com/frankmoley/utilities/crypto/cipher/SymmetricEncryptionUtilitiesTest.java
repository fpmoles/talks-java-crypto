package com.frankmoley.utilities.crypto.cipher;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Frank P. Moley III.
 */
class SymmetricEncryptionUtilitiesTest {

    private static final String AES = "AES";
    private static final String PLAIN_TEXT = "This is super secret text that we want to encrypt to send to our friend";
    private static final byte[] SECRET_KEY_BYTES = DatatypeConverter.parseHexBinary("2612A8908E6B7CF591C6C0C5E6385A9907E17F52D595236466BB0E53E704A334");
    private static final byte[] INITIALIZATION_VECTOR = DatatypeConverter.parseHexBinary("D722E67646B53FE52CE76B56AC25B8A6");
    private static final byte[] CIPHER_TEXT_BYTES = DatatypeConverter.parseHexBinary("0B0F48ADC7E12F0CFD6CED8C5D9EBC74E10171DA7512EEC5248F40DD60221895D703E35111253DB2EEDE9DCA546A4F5621FDA2BA61C04706DAF9D482F1FB116978852B0ED63CA062FC661E8A62DDCF19");

    @Test
    void getInstance() {
        SymmetricEncryptionUtilities utils = SymmetricEncryptionUtilities.getInstance();
        assertNotNull(utils);
        SymmetricEncryptionUtilities utils2 = SymmetricEncryptionUtilities.getInstance();
        assertSame(utils, utils2);
    }

    @Test
    void getAESKey() {
        SecretKey secretKey = SymmetricEncryptionUtilities.getInstance().getAESKey();
        assertNotNull(secretKey);
    }

    @Test
    void getInitializationVector() {
        byte[] initializationVector = SymmetricEncryptionUtilities.getInstance().getInitializationVector();
        assertNotNull(initializationVector);
    }

    @Test
    void performAESEncryption() {
        SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, 0, SECRET_KEY_BYTES.length, AES);
        byte[] cipherText = SymmetricEncryptionUtilities.getInstance().performAESEncryption(secretKey, INITIALIZATION_VECTOR, PLAIN_TEXT);
        assertNotNull(cipherText);
    }

    @Test
    void performAESDecryption() {
        SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, 0, SECRET_KEY_BYTES.length, AES);
        String plainText = SymmetricEncryptionUtilities.getInstance().performAESDecryption(secretKey, INITIALIZATION_VECTOR, CIPHER_TEXT_BYTES);
        assertEquals(PLAIN_TEXT, plainText);
    }
}