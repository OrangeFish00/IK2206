/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import java.lang.AssertionError;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.io.IOException;
import java.io.FileInputStream;
 
public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTHANDSHAKEPORT = 2206;
    public static final String DEFAULTHANDSHAKEHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    public static ClientHandshake clientHandshake;
    public static Arguments arguments;


    /**
     * Do handshake negotiation with server to authenticate and
     * learn parameters: session port, host, key, and IV
     * @throws CertificateException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws NoSuchPaddingException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws CertificateEncodingException 
     * @throws InvalidKeyException 
     */

    private static void doHandshake(Socket handshakeSocket) throws IOException, InvalidKeyException, CertificateEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateException {
        clientHandshake = new ClientHandshake(handshakeSocket);
    }

    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostName() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket 
     * and start port forwarder thread.
     */
    static public void startForwardClient() throws IOException, InvalidKeyException, CertificateEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateException, InvalidAlgorithmParameterException {

        /*
         * First, run the handshake protocol to learn session parameters.
         */
        Socket handshakeSocket = new Socket(arguments.get("handshakehost"),
                                            Integer.parseInt(arguments.get("handshakeport")));
  //      doHandshake(handshakeSocket,arguments.get("targethost"),arguments.get("targetport"),arguments.get("cacert"),arguments.get("usercert"),arguments.get("key"));
        doHandshake(handshakeSocket);
        /* 
         * Create a new listener socket for the proxy port. This is where
         * the user will connect.
         */
        ServerSocket proxySocket = new ServerSocket(Integer.parseInt(arguments.get("proxyport")));

        /* 
         * Tell the user, so the user knows the we are listening at the 
         * proxy port.
         */ 
        tellUser(proxySocket);

        /*
         * Set up port forwarding between proxy port and session host/port
         * that was learned from the handshake. 
         */
        ForwardServerClientThread forwardThread =
            new ForwardServerClientThread(proxySocket,clientHandshake.sessionHost, clientHandshake.sessionPort, clientHandshake.getSessionKey(),clientHandshake.getSessionIV());
        /* 
         * Launch the fowarder 
         */
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");      
        System.err.println(indent + "--proxyport=<portnumber>");      
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     * @throws CertificateException 
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws NoSuchPaddingException 
     * @throws InvalidKeySpecException 
     * @throws NoSuchAlgorithmException 
     * @throws CertificateEncodingException 
     * @throws InvalidKeyException 
     * @throws InvalidAlgorithmParameterException 
     */
    public static void main(String[] args) throws InvalidKeyException, CertificateEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, CertificateException, InvalidAlgorithmParameterException
    {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTHANDSHAKEPORT));
            arguments.setDefault("handshakehost", DEFAULTHANDSHAKEHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
            if (arguments.get("proxyport") == null) {
                throw new IllegalArgumentException("Proxy port not specified");
            }

        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        try {
            startForwardClient();
        } catch (IOException ex) {
            System.out.println(ex);
            System.exit(1);
        }
    }
}
