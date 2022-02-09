import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class SessionKey {

	private SecretKey skey;
		
	public SessionKey(Integer keylength) throws NoSuchAlgorithmException { 
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keylength); 
        this.skey = keyGen.generateKey();
	}
	
	public SessionKey(byte[] keybytes) {
		this.skey = new SecretKeySpec(keybytes, "AES");
	}
	
	public SecretKey getSecretKey() {
		return this.skey;
	}
	
	public byte[] getKeyBytes() {
		return this.skey.getEncoded();
		
	}

}
