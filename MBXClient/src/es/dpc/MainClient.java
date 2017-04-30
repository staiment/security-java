package es.dpc;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

public class MainClient {

	public static void main(String[] args) {
		try {
			// TODO Auto-generated method stub
			System.out.println("\nInitialize the environment map");
			HashMap env = new HashMap();

			// Provide the credentials required by the server to successfully
			// perform user authentication
			//
			String[] credentials = new String[] { "a" , "b" };
			env.put("jmx.remote.credentials", credentials);

			//Private client certs storage
			 System.setProperty("javax.net.ssl.keyStore",   "clientkeystore");
		       System.setProperty("javax.net.ssl.keyStoreType",   "JKS");
		       System.setProperty("javax.net.ssl.keyStorePassword",   "cambiar");
		     //Public server certs storage
		       System.setProperty("javax.net.ssl.trustStore",   "truststoreclient");
		       System.setProperty("javax.net.ssl.trustStoreType",   "JKS");
		       System.setProperty("javax.net.ssl.trustStorePassword",   "cambiar");
		       
			
			// Create an RMI connector client and
			// connect it to the RMI connector server
			//
			System.out.println("\nCreate an RMI connector client and " +
			                   "connect it to the RMI connector server");
			JMXServiceURL url = new JMXServiceURL(
			  "service:jmx:rmi:///jndi/rmi://localhost:33333/jmxrmi");
			JMXConnector jmxc = JMXConnectorFactory.connect(url, env);

			// Get an MBeanServerConnection
			//
			System.out.println("\nGet an MBeanServerConnection");
			MBeanServerConnection mbsc = jmxc.getMBeanServerConnection();

			// Get domains from MBeanServer
			//
			System.out.println("\nDomains:");
			String domains[] = mbsc.getDomains();
			for (int i = 0; i < domains.length; i++) {
			    System.out.println("\tDomain[" + i + "] = " + domains[i]);
			}
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}
