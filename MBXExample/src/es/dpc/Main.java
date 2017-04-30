package es.dpc;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.MalformedURLException;
import java.rmi.registry.LocateRegistry;
import java.util.HashMap;
import java.util.Map;

import javax.management.InstanceAlreadyExistsException;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.MalformedObjectNameException;
import javax.management.NotCompliantMBeanException;
import javax.management.ObjectName;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

public class Main {

	public static 		Test mbean2 = new Test(); 
	public static void main(String[] args) {
		//Properties for trust & server keystores
		 System.setProperty("javax.net.ssl.keyStore",   "serverkeystore");
	       System.setProperty("javax.net.ssl.keyStoreType",   "JKS");
	       System.setProperty("javax.net.ssl.keyStorePassword",   "cambiar");
	     
	       System.setProperty("javax.net.ssl.trustStore",   "truststoreserver");
	       System.setProperty("javax.net.ssl.trustStoreType",   "JKS");
	       System.setProperty("javax.net.ssl.trustStorePassword",   "cambiar");
	       
	       //Ensure the client cert must be validate
	       System.setProperty("com.sun.management.jmxremote.registry.ssl", "true");
	       System.setProperty("com.sun.management.jmxremote.ssl.need.client.auth",   "true");
	       
	try {
		MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
		//MDB Register name "domain_name:type=ObjectName"
		ObjectName name = new ObjectName("es.dpc:type=Test"); 

		mbs.registerMBean(mbean2, name); 

		 Map env=new HashMap();
		 //Define autenticator class
         env.put(JMXConnectorServer.AUTHENTICATOR, new RealmAutenticator());
	       
	       /**********************************************************/
	       //define secure ssl sockets for comunication
	       SslRMIClientSocketFactory csf = new SslRMIClientSocketFactory();
           SslRMIServerSocketFactory ssf = new SslRMIServerSocketFactory(null,null,true);
           env.put(RMIConnectorServer.RMI_CLIENT_SOCKET_FACTORY_ATTRIBUTE,csf);
           env.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE,ssf);

           
	       /*********************************************************/
		 String host="localhost";
		 int registryPort=33333;
		 int serverPort=44444;
		 //create local registry for rmi objects
		 LocateRegistry.createRegistry(registryPort);
		 String urlS = String.format("service:jmx:rmi://localhost:%d/jndi/rmi://%s:%d/jmxrmi",serverPort,host,registryPort);
		 JMXServiceURL url=new JMXServiceURL(urlS);
		 
		  JMXConnectorServer cs = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbs);
			System.out.println(urlS);
		  cs.start();
	
		System.out.println("Waiting forever..."); 
		Thread.sleep(Long.MAX_VALUE);
	} catch (MalformedObjectNameException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InstanceAlreadyExistsException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (MBeanRegistrationException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NotCompliantMBeanException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InterruptedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (MalformedURLException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();

	} 
}
}
