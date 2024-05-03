package advanced.encryption.standard.algorithm;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MyAES {

	private static SecretKeySpec secretKey;
	private static byte[] key;
	
	// Setting the key
	public static void setKey(String myKey) {
		try {
			key = myKey.getBytes("UTF-8");
			/*
			Checksum: Error detection method
			Hash Function: It is a function to produce checksum
			Hash Value: Is a numeric value of fixed length that uniquely identifies data
			Message Digest: It is a fixed sized numeric representation of the contents of the message
			computed by a function. In Java, MessageDigest class provides functionality of a message digest
			using algorithms such as SHA-1 or SHA-256
			SHA stands for Secure Hashing Algorithm
			*/
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16); // Original, new length
			secretKey = new SecretKeySpec(key, "AES");
		} catch (Exception e) {
			// TODO: handle exception
		}
	}
	// Encryption
	public static String encrypt(String strToEncrypt, String sec) {
	    try {
	        setKey(sec);
	        // Generate a random IV
	        var random = new SecureRandom();
	        byte[] iv = new byte[16]; // IV size for AES is 16 bytes
	        random.nextBytes(iv);
	        var ivParameterSpec = new IvParameterSpec(iv);
	        
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
	        // Concatenate IV and ciphertext for later use in decryption
	        byte[] encryptedBytes = cipher.doFinal(strToEncrypt.getBytes("UTF-8"));
	        byte[] combined = new byte[iv.length + encryptedBytes.length];
	        System.arraycopy(iv, 0, combined, 0, iv.length);
	        System.arraycopy(encryptedBytes, 0, combined, iv.length, encryptedBytes.length);
	        
	        return Base64.getEncoder().encodeToString(combined);
	        
	    } catch (Exception e) {
	        e.printStackTrace(); 
	    }
	    return null;
	}

	// Decryption
	public static String decrypt(String strToDecrypt, String sec) {
	    try {
	        setKey(sec);
	        byte[] combined = Base64.getDecoder().decode(strToDecrypt);
	        byte[] iv = Arrays.copyOfRange(combined, 0, 16); // IV size for AES is 16 bytes
	        byte[] encryptedBytes = Arrays.copyOfRange(combined, 16, combined.length);
	        var ivParameterSpec = new IvParameterSpec(iv);
	        
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
	        return new String(cipher.doFinal(encryptedBytes), "UTF-8");
	        
	    } catch (Exception e) {
	        e.printStackTrace(); 
	    }
	    return null;
	}
		
}
