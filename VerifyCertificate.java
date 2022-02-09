import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;

public class VerifyCertificate {
       private static X509Certificate certCA;
       private static X509Certificate certUSER;
       
	   public static void main(String[] args) throws IOException, FileNotFoundException, CertificateParsingException, CertificateException, Exception {
	        String ca = args[0];
	        String user = args[1];
	        
	        certCA = getCert(ca);
	        certUSER = getCert(user);
	       /* FileInputStream inputCA = new FileInputStream(ca);
	        FileInputStream inputUSER = new FileInputStream(user);
	        CertificateFactory cf = CertificateFactory.getInstance("X.509");

	        certCA = (X509Certificate) cf.generateCertificate(inputCA);
	        certUSER = (X509Certificate) cf.generateCertificate(inputUSER);
	        inputCA.close();
	        inputUSER.close();*/
	        
            System.out.println(certCA.getSubjectDN());
            System.out.println(certUSER.getSubjectDN());

	        try { 
	            verify(certCA, certCA);
	            verify(certCA, certUSER);
	            validate(certCA);
	            validate(certUSER);

	            System.out.println("Pass");
	        } catch (Exception e) {
	            System.out.println("Fail");
	            System.out.println(e.getMessage());
	        }
	    }

	    public static void validate(X509Certificate cert) throws  CertificateExpiredException, CertificateNotYetValidException {
	        cert.checkValidity();
	    }

	    public static void verify(X509Certificate CA, X509Certificate cert) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
	        PublicKey pkey;
	        pkey = CA.getPublicKey();
	        cert.verify(pkey);
	    }

		public static X509Certificate getCert(String cert) throws CertificateException, CertificateParsingException, IOException {
			X509Certificate C;
			FileInputStream input = new FileInputStream(cert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			C = (X509Certificate) cf.generateCertificate(input);
			input.close();
			return C;
		}
		public static X509Certificate getCert1(String cert) throws CertificateException, CertificateParsingException, IOException {
			X509Certificate C;
			byte [] temp = java.util.Base64.getDecoder().decode(cert);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			InputStream input = new ByteArrayInputStream(temp);
			C = (X509Certificate) cf.generateCertificate(input);
			input.close();
			return C;
		}
		


}

 