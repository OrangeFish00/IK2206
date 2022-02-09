import java.io.*;
import java.nio.file.*;
import java.security.InvalidKeyException;
import java.security.*;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.spec.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class HandshakeCrypto {
	
	public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);
	}
	
	public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(ciphertext);
	}
	
	public static PublicKey getPublicKeyFromCertFile(String certfile) throws FileNotFoundException, CertificateException {
		FileInputStream input = new FileInputStream(certfile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(input);
		PublicKey pubkey = cert.getPublicKey();
		return pubkey;
	}
	
	public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		 byte[] pribyte = Files.readAllBytes(Paths.get(keyfile));
	     PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pribyte);
	     KeyFactory kf = KeyFactory.getInstance("RSA");
	     PrivateKey mprikey = kf.generatePrivate(spec);
	     return mprikey;
	}
    
}
