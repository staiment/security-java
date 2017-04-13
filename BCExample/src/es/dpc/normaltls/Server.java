package es.dpc.normaltls;

import java.io.IOException;
import java.net.ServerSocket;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Server {

	 private ServerSocket serverSocket;
	 
	 private int count=0;
	
	public Server(int port) {
		  
		 

          try {
        	   ServerSocketFactory f = SSLServerSocketFactory.getDefault();
        	   serverSocket=(ServerSocket)f.createServerSocket( port, 10);
        	   while(true){                
        		   System.out.println("Waiting for incoming connections...");
                   SSLSocket sslsocket = (SSLSocket) serverSocket.accept();
                   System.out.println("New Client accepted");

                   ServerClientProcessor proc=new ServerClientProcessor(sslsocket, "file_"+(++count));
                   new Thread(proc).start();      
               } 
          } catch(IOException e) {
               e.printStackTrace();
          }
	}
	
	public static void main(String[] args) {

		
		 System.setProperty("javax.net.ssl.keyStore",   "servercerts/serverkeystore");
	       System.setProperty("javax.net.ssl.keyStoreType",   "JKS");
	       System.setProperty("javax.net.ssl.keyStorePassword",   "cambiar");
	     
	       System.setProperty("javax.net.ssl.trustStore",   "servercerts/truststoreserver");
	       System.setProperty("javax.net.ssl.trustStoreType",   "JKS");
	       System.setProperty("javax.net.ssl.trustStorePassword",   "cambiar");
	       
	       //Ensure the client cert must be validate
	       System.setProperty("com.sun.management.jmxremote.registry.ssl", "true");
	       System.setProperty("com.sun.management.jmxremote.ssl.need.client.auth",   "true");
	       
		new Server(5555);
	}
}
