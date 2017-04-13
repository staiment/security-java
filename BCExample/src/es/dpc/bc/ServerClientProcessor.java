package es.dpc.bc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ServerClientProcessor implements Runnable {
	
	private Socket socket;
	
	private String pathFile;
	
	public ServerClientProcessor(Socket socket, String pathFile) {
		this.socket=socket;
		this.pathFile=pathFile;
	}
	
	@Override
	public void run() {
		try {
			InputStream inputStream = socket.getInputStream();
			OutputStream out=new FileOutputStream(new File(pathFile));
			int numBytes=-1;
			byte[] arr=new byte[1024];
			while((numBytes=inputStream.read(arr))!=-1){
				out.write(arr,0,numBytes);
				out.flush();
			}
			out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
