package com.frankmoley.utilities.crypto.digest;

import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import javax.xml.crypto.Data;
import java.security.SecureRandom;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Frank P. Moley III.
 */
class HashUtilitiesTest {

    private static String PASSWORD = "correct horse battery staple"; //https://xkcd.com/936/
    private static String PASSWORD_HASH = "$2a$12$NdwNRewb2LPwxNCHN.1DFeuidTn6w1f3hmr/22lqhLbQcOebVNDHm";

    @Test
    void getInstance() {
        HashUtilities utils = HashUtilities.getInstance();
        assertNotNull(utils);
        HashUtilities utils2 = HashUtilities.getInstance();
        assertSame(utils, utils2);
    }

    @Test
    void createSHA256Hash() {
        byte[] inputData = UUID.randomUUID().toString().getBytes();
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        byte[] hash = HashUtilities.getInstance().createSHA256Hash(inputData, salt);
        assertNotNull(hash);
        byte[] hash2 = HashUtilities.getInstance().createSHA256Hash(inputData, salt);
        assertEquals(DatatypeConverter.printHexBinary(hash), DatatypeConverter.printHexBinary(hash2));
    }

    @Test
    void hashPassword() {
        String passwordHash = HashUtilities.getInstance().hashPassword(PASSWORD);
        assertNotNull(passwordHash);
    }

    @Test
    void verifyPassord() {
        assertTrue(HashUtilities.getInstance().verifyPassord(PASSWORD, PASSWORD_HASH));
    }
}