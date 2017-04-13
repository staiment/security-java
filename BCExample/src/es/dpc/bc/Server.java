package es.dpc.bc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.crypto.agreement.DHStandardGroups;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsRSAKeyExchange;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class Server {

	private ServerSocket serverSocket;

	private int count=0;

	public Server(int port,String persistentKeyStore,String strTrustStore) {

		try {
			if(!new File(persistentKeyStore).exists()){
				createKeyStore(persistentKeyStore);
			}
			final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			final KeyStore trustStore=KeyStore.getInstance(KeyStore.getDefaultType());
			
			char[] pass=new char[]{'c','a','m','b','i','a','r'};
			keyStore.load(new FileInputStream(new File(persistentKeyStore)),pass );
			trustStore.load(new FileInputStream(new File(strTrustStore)),pass );
			for (int i = 0; i < pass.length; i++) {
				pass[i]='\0';		
			}

	
			try {
				
				serverSocket=new ServerSocket(port,10);
				while(true){                
					try {
						System.out.println("Waiting for incoming connections...");
						final Socket socket =  serverSocket.accept();
						System.out.println("New Client accepted");
						// Validate Secure layer
						Thread serv=new Thread(new Runnable() {
							
							@Override
							public void run() {
								// TODO Auto-generated method stub
								try {
									final X509Certificate certificate = (X509Certificate)keyStore.getCertificate("ServerCert");
								Enumeration<String> aliases = keyStore.aliases();
								while (aliases.hasMoreElements()) {
									String string = (String) aliases.nextElement();
									System.out.println(string);
								}
									TlsServerProtocol tlsServerProtocol = new TlsServerProtocol(
										    socket.getInputStream(), socket.getOutputStream(),new SecureRandom());
									tlsServerProtocol.accept( new TlsCustomServer(certificate,keyStore,trustStore));						
									ServerClientProcessor proc=new ServerClientProcessor(socket, "file_"+(++count));
									new Thread(proc).start();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								} catch (KeyStoreException e1) {
									// TODO Auto-generated catch block
									e1.printStackTrace();
								}   
								
								

							}
						});
						serv.start();
					} catch (Exception e) {
						e.printStackTrace();
					}      
				} 
			} catch(IOException e) {
				e.printStackTrace();
			}
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void createKeyStore(String persistentKeyStore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException, SignatureException {


		//new keystore
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] pass=new char[]{'c','a','m','b','i','a','r'};
		keyStore.load(null,pass );
		keyStore.store(new FileOutputStream(new File(persistentKeyStore)), pass);
		
		//new cert
		Date startDate = new Date();              // time from which certificate is valid
		Calendar expDate = GregorianCalendar.getInstance();
		expDate.add(GregorianCalendar.YEAR, 1000);
		Date expiryDate = expDate.getTime();             // time after which certificate is not valid
		BigInteger serialNumber = new BigInteger(""+System.currentTimeMillis());     // serial number for certificate
		serialNumber=serialNumber.nextProbablePrime();
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");//ELIPTIC CURVE NAME
		KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
		g.initialize(ecSpec, new SecureRandom());
		KeyPair keyPair = g.generateKeyPair(); // EC public/private key pair
		X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		X500Principal              dnName = new X500Principal("CN=DPC CA Certificate");
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(dnName);
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(dnName);                       // note: same as issuer
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256withECDSA");
		X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
		
		//store cert
		keyStore.setCertificateEntry("ServerCert", cert);
		java.security.cert.Certificate[] chain = {cert};
		keyStore.setKeyEntry("ServerCertKey", keyPair.getPrivate(),pass,chain);

		keyStore.store(new FileOutputStream(new File(persistentKeyStore)), pass);
		for (int i = 0; i < pass.length; i++) {
			pass[i]='\0';		
		}
	}

	public static void main(String[] args) {
		java.security.Security.addProvider(new BouncyCastleProvider());

		new Server(5555,"bcservercerts/serverkeystore","bcservercerts/servertruststore");
	}
}
