/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.*;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.sql.Timestamp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.net.ServerSocket;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
	private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sKey;
    public byte[] sIV;
    public X509Certificate ccert;
    public X509Certificate scert;
    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     * @throws IOException 
     * @throws CertificateException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws InvalidAlgorithmParameterException 
     * @throws NoSuchPaddingException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws InvalidKeySpecException 
     */ 
    
    public ServerHandshake(Socket handshakeSocket) throws IOException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();
        MessageDigest msgin = MessageDigest.getInstance("SHA-256");
        MessageDigest msgout = MessageDigest.getInstance("SHA-256");
        
        VerifyClient(handshakeSocket,ForwardServer.arguments.get("cacert"), msgin);
        ServerSend(handshakeSocket, ForwardServer.arguments.get("usercert"), msgout);
        VerifyCert(handshakeSocket, msgin);
        StartSession(handshakeSocket, sessionHost, sessionPort, msgout);
        SignatureDecrypt(handshakeSocket, msgin);
        Over(handshakeSocket, msgout, HandshakeCrypto.getPrivateKeyFromKeyFile(ForwardServer.arguments.get("key")));
    }
    
  //s get c hello
    public void VerifyClient(Socket handshakeSocket, String cert, MessageDigest msgin) throws IOException, CertificateException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.recv(handshakeSocket);
    	hsmessage.updateDigest(msgin);

    	if(hsmessage.getParameter("MessageType").equals("ClientHello")) {
        	String temp = hsmessage.getParameter("Certificate");
        	ccert = VerifyCertificate.getCert1(temp);
            X509Certificate xtemp = VerifyCertificate.getCert(cert);
    		try {    			
    			VerifyCertificate.verify(xtemp, ccert); 
    			Logger.log("VerifyClient done");
    		 }
    		catch (Exception e){
    			Logger.log("VerifyClient failed");
    			handshakeSocket.close();
    		}		
    	}
    	else {
    		Logger.log("Not match");
    		handshakeSocket.close();
    	}
    }
    
    //s send hello to c
    public void ServerSend(Socket handshakeSocket, String cert, MessageDigest msgout) throws CertificateException, IOException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	scert = VerifyCertificate.getCert(cert);
    	hsmessage.putParameter("MessageType", "ServerHello");
    	String temp = Base64.getEncoder().encodeToString(scert.getEncoded());
    	hsmessage.putParameter("Certificate", temp);
    	hsmessage.updateDigest(msgout);
    	hsmessage.send(handshakeSocket);
    	Logger.log("ServerSend done");
    }
    
    //s verify certificate from c
    public void VerifyCert(Socket handshakeSocket, MessageDigest msgin) throws IOException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.recv(handshakeSocket);
    	hsmessage.updateDigest(msgin);
    	
    	if(hsmessage.getParameter("MessageType").equals("Forward")) {
    		targetHost = hsmessage.getParameter("TargetHost");
    		targetPort = Integer.parseInt(hsmessage.getParameter("TargetPort"));
    		Logger.log("VerifyCert done");
    	}
    	else {
    		Logger.log("VerifyCert failed");
    		handshakeSocket.close();
    	}
    }
    
    //session can start, so s should generate key&iv
    public void StartSession(Socket handshakeSocket, String sessionHost, int sessionPort, MessageDigest msgout) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException {
    	PublicKey pkey = ccert.getPublicKey();
    	HandshakeMessage hsmessage = new HandshakeMessage();   	
    	SessionEncrypter sencrypt = new SessionEncrypter(128);

    	sKey = sencrypt.getKeyBytes();
    	sIV = sencrypt.getIVBytes();
    	byte[] temp1 = HandshakeCrypto.encrypt(sKey, pkey);
        String t1 = Base64.getEncoder().encodeToString(temp1);
		byte[] temp2 = HandshakeCrypto.encrypt(sIV, pkey);
		String t2 = Base64.getEncoder().encodeToString(temp2);
		
		hsmessage.putParameter("MessageType","Session");
		hsmessage.putParameter("SessionKey",t1);
		hsmessage.putParameter("SessionIV",t2);
		hsmessage.putParameter("SessionHost",sessionHost);
		hsmessage.putParameter("SessionPort",String.valueOf(sessionPort));
		hsmessage.updateDigest(msgout);
		hsmessage.send(handshakeSocket);
		Logger.log("StartSession done");
    }

    public byte[] getSessionKey() {
    	return sKey;
    }
    
    public byte[] getSessionIV() {
    	return sIV;
    }
    
/*	public static X509Certificate getCert1(String cert) throws CertificateException, IOException {
		X509Certificate C;
		byte [] temp = java.util.Base64.getDecoder().decode(cert);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		InputStream input = new ByteArrayInputStream(temp);
		C = (X509Certificate) cf.generateCertificate(input);
		input.close();
		return C;
	}*/

    //extra
    //1.recive msg from c 2.check timestamp 3.decrypt signature
    public void SignatureDecrypt(Socket handshakeSocket, MessageDigest msgin) throws IOException, CertificateParsingException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.recv(handshakeSocket);
    	PublicKey pkey = ccert.getPublicKey();
    	
    	Timestamp timestamp = new Timestamp(System.currentTimeMillis());
    	byte[] getts = Base64.getMimeDecoder().decode(hsmessage.getParameter("TimeStamp"));
		//String temp2 = Arrays.toString(HandshakeCrypto.decrypt(getts, pkey));
		String temp2 = new String(HandshakeCrypto.decrypt(getts, pkey), StandardCharsets.UTF_8);
		Timestamp timestamp2 = Timestamp.valueOf(temp2);
		
		Logger.log("S SignatureDecrypt  done");
        if(Math.abs(timestamp.getTime()-timestamp2.getTime())>1000) {
        	Logger.log("Handshake timeout");
        }
        
        byte[] getsign = Base64.getMimeDecoder().decode(hsmessage.getParameter("Signature"));
        byte[] temp3 = HandshakeCrypto.decrypt(getsign, pkey);
        if (!Arrays.equals(temp3, msgin.digest())) {
        	Logger.log("Signature wrong");
        }
    }
    
    //tell c over
    public void Over(Socket handshakeSocket, MessageDigest msgout, PrivateKey pkey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	
    	byte[] temp = HandshakeCrypto.encrypt(msgout.digest(), pkey);
    	//String temp1 = Arrays.toString(Base64.getEncoder().encode(temp));
		//hsmessage.putParameter("Signature", temp1);
		hsmessage.putParameter("Signature", new String(Base64.getEncoder().encode(temp)));
    	
    	Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        byte[] temp2 = timestamp.toString().substring(0,19).getBytes(StandardCharsets.UTF_8);
        byte[] temp3 = HandshakeCrypto.encrypt(temp2, pkey);
        hsmessage.putParameter("TimeStamp", new String(Base64.getEncoder().encode(temp3)));
    	hsmessage.send(handshakeSocket);
    	handshakeSocket.close();
    	Logger.log("Handshake done");
    }
    
}
