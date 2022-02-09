import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.*;

public class SessionDecrypter {
    private Cipher cipher;
    private SessionKey skey;
    private IvParameterSpec iv;
	private static String str = "AES/CTR/NoPadding";
	
    public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	cipher = Cipher.getInstance(str);
    	this.skey = new SessionKey(keybytes);
    	this.iv = new IvParameterSpec(ivbytes);
    	this.cipher.init(Cipher.DECRYPT_MODE, this.skey.getSecretKey(), this.iv);
    }
    
   public CipherInputStream openCipherInputStream(InputStream input) {
        return new CipherInputStream(input, cipher);
    }

}
