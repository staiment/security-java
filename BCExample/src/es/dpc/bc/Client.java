package es.dpc.bc;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.UnknownHostException;
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
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientProtocol;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsECDHKeyExchange;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsRSAKeyExchange;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class Client {
	
	private static class Sender implements Runnable{
		File file;
		
		String server ;
		
		int port;
		
		KeyStore keyStore;
		
		KeyStore trustStore;
		
		public Sender(String server, int port,File file, String persistentKeyStore,String strTrustStore) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, NoSuchProviderException, InvalidAlgorithmParameterException, IllegalStateException, SignatureException, IOException {
			this.file=file;
			this.server=server;
			this.port=port;
			if(!new File(persistentKeyStore).exists()){
				createKeyStore(persistentKeyStore);
			}
			char[] pass=new char[]{'c','a','m','b','i','a','r'};
			
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(new FileInputStream(new File(persistentKeyStore)),pass );
			
			trustStore=KeyStore.getInstance(KeyStore.getDefaultType());
			trustStore.load(new FileInputStream(new File(strTrustStore)), pass);
			
			for (int i = 0; i < pass.length; i++) {
				pass[i]='\0';		
			}

		}
		
		@Override
		public void run() {
			try {
				System.out.println("Init thread for file "+file.getAbsolutePath());
				Socket socket = new Socket("localhost", 5555);
				final X509Certificate certificate = (X509Certificate)keyStore.getCertificate("ClientCert");
				
				TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(    
				    socket.getInputStream(), socket.getOutputStream(), new SecureRandom());
				tlsClientProtocol.connect(new TlsCustomClient(null, certificate, keyStore,trustStore));
				
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
			} catch (KeyStoreException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
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
			keyStore.setCertificateEntry("ClientCert", cert);
			java.security.cert.Certificate[] chain = {cert};
			keyStore.setKeyEntry("ClientCertKey", keyPair.getPrivate(),pass,chain);

			keyStore.store(new FileOutputStream(new File(persistentKeyStore)), pass);
			for (int i = 0; i < pass.length; i++) {
				pass[i]='\0';		
			}
		}
	}

	
	private String server;
	
	private int port;
	
	
	public Client(String server, int port, String path,String keyStorePath,String trustStorePath) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, NoSuchProviderException, InvalidAlgorithmParameterException, IllegalStateException, SignatureException, IOException {
		this.server=server;
		this.port=port;
		File dir=new File(path);
		File[] files = dir.listFiles();
		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			new Thread(new Sender(server, port, file,keyStorePath,trustStorePath), "Thread for "+file.getAbsolutePath()).start();
		}
	}

	public static void main(String[] args) {
		java.security.Security.addProvider(new BouncyCastleProvider());

		try {
			new Client("192.168.1.37",5555,".\\files","bcclientcerts/clientkeystore", "bcclientcerts/clienttruststore");
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
}
