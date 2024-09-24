package org.example;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class SimpleEncryptionDecryption {
    public static String encrypt(String plainText, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encryptedMessage = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    public static String decrypt(String cipherText, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decodeMessage = Base64.getDecoder().decode(cipherText);
        byte[] decryptedMessage = cipher.doFinal(decodeMessage);
        return new String(decryptedMessage);
    }

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        try {
            System.out.println("Enter the message to encrypt");
            String message = scanner.nextLine();
            System.out.println("Enter 16 characters: ");
            String secretKey = scanner.nextLine();
            if (secretKey.length() != 16) {
                System.out.println("Please enter 16 Characters!!!");
                return;
            }
            String encryptedMessage = SimpleEncryptionDecryption.encrypt(message, secretKey);
            System.out.println("Encrypted Message: " + encryptedMessage);
            String decryptedMessage = decrypt(encryptedMessage, secretKey);
            System.out.println("Decryption message: " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
