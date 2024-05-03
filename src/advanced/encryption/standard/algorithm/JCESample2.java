package advanced.encryption.standard.algorithm;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

// DES - Data Encryption Standard
// AES - Advanced Encryption Standard

public class JCESample2 {

	public static void main(String[] args) {
		try {
			KeyGenerator kg = KeyGenerator.getInstance("DES");
			SecretKey myDESKey = kg.generateKey();
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, myDESKey);
			byte[] text = "RT89Loc5".getBytes();
			System.out.println("Text in bytes: " + text);
			System.out.println("Text: " + new String(text));
			// Encrypt text
			byte[] textEncrypt = cipher.doFinal(text);
			System.out.println("Text in bytes: " + textEncrypt);
			System.out.println("Text Encrypted: " + new String(textEncrypt));
			cipher.init(Cipher.DECRYPT_MODE, myDESKey); // Decrypt 
			byte[] textDecrypt = cipher.doFinal(textEncrypt);
			System.out.println("Text Decrypted: " + new String(textDecrypt));
		} catch (Exception e) {
			// TODO: handle exception
		}
	}
	
}
