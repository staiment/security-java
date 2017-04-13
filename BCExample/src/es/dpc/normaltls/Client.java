package es.dpc.normaltls;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

public class Client {
	
	private static class Sender implements Runnable{
		File file;
		
		String server ;
		
		int port;
		
		public Sender(String server, int port,File file) {
			this.file=file;
			this.server=server;
			this.port=port;
		}
		
		@Override
		public void run() {
			try {
				System.out.println("Init thread for file "+file.getAbsolutePath());
				SocketFactory sf = SSLSocketFactory.getDefault();
				Socket socket = sf.createSocket(server, port);
				OutputStream outputStream = socket.getOutputStream();
				FileInputStream fis=new FileInputStream(file);
				byte[] arr=new byte[10];
				int length=-1;
				while((length=fis.read(arr))!=-1){
					outputStream.write(arr,0,length);
					outputStream.flush();
			//		Thread.currentThread().sleep(2000);
				}
				outputStream.close();
				System.out.println("End of thread for "+file.getAbsolutePath());
			} catch (UnknownHostException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
//			} catch (InterruptedException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//			
		}
	}

	
	private String server;
	
	private int port;
	
	
	public Client(String server, int port, String path) {
		this.server=server;
		this.port=port;
		File dir=new File(path);
		File[] files = dir.listFiles();
		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			new Thread(new Sender(server, port, file), "Thread for "+file.getAbsolutePath()).start();
		}
	}

	public static void main(String[] args) {
		//Private client certs storage
		 System.setProperty("javax.net.ssl.keyStore",   "clientcerts/clientkeystore");
	       System.setProperty("javax.net.ssl.keyStoreType",   "JKS");
	       System.setProperty("javax.net.ssl.keyStorePassword",   "cambiar");
	     //Public server certs storage
	       System.setProperty("javax.net.ssl.trustStore",   "clientcerts/truststoreclient");
	       System.setProperty("javax.net.ssl.trustStoreType",   "JKS");
	       System.setProperty("javax.net.ssl.trustStorePassword",   "cambiar");
	       
		
		new Client("192.168.1.37",5555,".\\files");
	}
}
