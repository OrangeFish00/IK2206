import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.*;


public class SessionEncrypter {
	private SessionKey skey;
	private IvParameterSpec iv;
	private Cipher cipher;
	private static String str = "AES/CTR/NoPadding";

	
    public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	this.skey = new SessionKey(keylength);
    	cipher = Cipher.getInstance(str);
    	
    	byte[] ivTemp =new byte[cipher.getBlockSize()];
    	new SecureRandom().nextBytes(ivTemp);
    	this.iv = new IvParameterSpec(ivTemp);    	
    	this.cipher.init(Cipher.ENCRYPT_MODE, this.skey.getSecretKey(), this.iv);
		
	}
    
    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	cipher = Cipher.getInstance(str);
    	this.skey = new SessionKey(keybytes);
    	this.iv = new IvParameterSpec(ivbytes);
    	this.cipher.init(Cipher.ENCRYPT_MODE, this.skey.getSecretKey(), this.iv);
    }
	public byte[] getKeyBytes() {
		return this.skey.getSecretKey().getEncoded();
	}
	public byte[] getIVBytes() {
		return this.iv.getIV();   
  }

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output, cipher);
    }
}

