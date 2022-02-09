/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.sql.Timestamp;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    public X509Certificate ctemp;

    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345;    

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sKey;
    public byte[] sIV;
    public X509Certificate ccert;
    public X509Certificate scert;
    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws NoSuchPaddingException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     * @throws CertificateException 
     * @throws CertificateEncodingException 
     */ 
    
    //public ClientHandshake(Socket handshakeSocket, String prikey, String targethost, String targetport, String cacert, String usercert) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, CertificateException {
    public ClientHandshake(Socket handshakeSocket) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateEncodingException, CertificateException {	
         MessageDigest msgin = MessageDigest.getInstance("SHA-256");
         MessageDigest msgout = MessageDigest.getInstance("SHA-256");
         
    	 ClientHello(handshakeSocket,ForwardClient.arguments.get("usercert"), msgout);
    	 String cert = ForwardClient.arguments.get("cacert");
    	 ServerHello(handshakeSocket, cert, msgin);
         ClientForward(handshakeSocket, ForwardClient.arguments.get("targethost"), ForwardClient.arguments.get("targetport"), msgout);
         String pkey = ForwardClient.arguments.get("key");
         ReceiveSession(handshakeSocket, pkey, msgin);
         SignatureEncrypt(handshakeSocket, pkey, msgout);
         SignatureDecrypt(handshakeSocket, cert, msgin);
         handshakeSocket.close();
    }
    
    //c send hello to s
    public void ClientHello(Socket handshakeSocket, String cert, MessageDigest msgout) throws CertificateException, IOException, CertificateEncodingException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	ccert = VerifyCertificate.getCert(cert);
    	hsmessage.putParameter("MessageType", "ClientHello");
    	String temp = Base64.getEncoder().encodeToString(ccert.getEncoded());
    	hsmessage.putParameter("Certificate", temp);
    	hsmessage.updateDigest(msgout);
    	hsmessage.send(handshakeSocket);
    	Logger.log("Clienthello done");
    	
    }
    
    //c get s hello
    public void ServerHello(Socket handshakeSocket, String cert, MessageDigest msgin) throws IOException, CertificateException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.recv(handshakeSocket);
    	hsmessage.updateDigest(msgin);

    	if(hsmessage.getParameter("MessageType").equals("ServerHello")) {
        	String temp = hsmessage.getParameter("Certificate");
        	scert = VerifyCertificate.getCert1(temp);
            X509Certificate xtemp = VerifyCertificate.getCert(cert);
            ctemp = scert;
    		try {    			
    			VerifyCertificate.verify(xtemp, scert); 
    			Logger.log("Serverhello done");
    		 }
    		catch (Exception e){
    			Logger.log("Serverhello failed");
    			handshakeSocket.close();
    		}		
    	}
    	else {
    		Logger.log("Not match");
    		handshakeSocket.close();
    	}	
    }
    
    //c verify certificate
    public void ClientForward(Socket handshakeSocket, String targethost, String targetport, MessageDigest msgout) throws IOException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.putParameter("MessageType", "Forward");
    	hsmessage.putParameter("TargetHost", targethost);
    	hsmessage.putParameter("TargetPort", targetport);
    	hsmessage.updateDigest(msgout);
    	hsmessage.send(handshakeSocket);
    	Logger.log("ClientForward done");
    }
    
    //session start by s
    public void ReceiveSession(Socket handshakeSocket, String prikey, MessageDigest msgin) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.recv(handshakeSocket);
    	hsmessage.updateDigest(msgin);
    	if(hsmessage.getParameter("MessageType").equals("Session")) {
    		PrivateKey pkey = HandshakeCrypto.getPrivateKeyFromKeyFile(prikey); 
    		byte[] temp1 = Base64.getDecoder().decode(hsmessage.getParameter("SessionKey"));
            sKey = HandshakeCrypto.decrypt(temp1, pkey);
    		byte[] temp2 = Base64.getDecoder().decode(hsmessage.getParameter("SessionIV"));
            sIV = HandshakeCrypto.decrypt(temp2, pkey);
            sessionHost = hsmessage.getParameter("SessionHost");
            sessionPort = Integer.parseInt(hsmessage.getParameter("SessionPort"));
            Logger.log("ReceiveSession done");

    	}
    	else {
    		Logger.log("ReceiveSession failed");
    		handshakeSocket.close();
    	}
    }
    
    public byte[] getSessionKey() {
    	return sKey;
    }
    
    public byte[] getSessionIV() {
    	return sIV;
    }
    
    //extra part
    //1.get signature 2.timestamp 3.encrypt msg to s
    public void SignatureEncrypt(Socket handshakeSocket, String prikey, MessageDigest msgout) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
    	PrivateKey pkey = HandshakeCrypto.getPrivateKeyFromKeyFile(prikey); 
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	
    	byte[] temp = HandshakeCrypto.encrypt(msgout.digest(), pkey);
    	//String temp1 = Arrays.toString(Base64.getEncoder().encode(temp));
        //hsmessage.putParameter("Signature", temp1);
        hsmessage.putParameter("Signature", new String(Base64.getEncoder().encode(temp)));
    	
    	Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        //byte[] ts = sdf.format(timestamp).getBytes(StandardCharsets.UTF_8);
        byte[] temp2 = timestamp.toString().substring(0,19).getBytes(StandardCharsets.UTF_8);
        byte[] temp3 = HandshakeCrypto.encrypt(temp2, pkey);
        hsmessage.putParameter("TimeStamp", new String(Base64.getEncoder().encode(temp3)));
    	//byte[] temp2 = HandshakeCrypto.encrypt(ts, pkey);
    	//String temp3 = Arrays.toString(Base64.getEncoder().encode(temp2));
        //hsmessage.putParameter("TimeStamp", temp3);
        hsmessage.send(handshakeSocket);
        Logger.log("SignatureEncrypt done");
    }
    
    //1.recive msg from s 2.check timestamp 3.decrypt signature
    //getTime() returns the value in milliseconds
    public void SignatureDecrypt(Socket handshakeSocket, String cert, MessageDigest msgin) throws IOException, CertificateParsingException, CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
    	HandshakeMessage hsmessage = new HandshakeMessage();
    	hsmessage.recv(handshakeSocket);
    	
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        byte[] getts = Base64.getMimeDecoder().decode(hsmessage.getParameter("TimeStamp"));
        
        String temp2 = new String(HandshakeCrypto.decrypt(getts,ctemp.getPublicKey()),  StandardCharsets.UTF_8);
        Timestamp timestamp2 = Timestamp.valueOf(temp2);
        Logger.log("C SignatureDecrypt  done");
        if(Math.abs(timestamp.getTime()-timestamp2.getTime())>1000) {
        	Logger.log("Handshake timeout");
        }
        
        byte[] getsign = Base64.getMimeDecoder().decode(hsmessage.getParameter("Signature"));
        byte[] temp3 = HandshakeCrypto.decrypt(getsign, ctemp.getPublicKey());
        if (!Arrays.equals(temp3, msgin.digest())) {
        	Logger.log("Signature wrong");
        }
    }

}
