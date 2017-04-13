package es.dpc.bc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.FileSystem;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class Setup {
	private static X509Certificate createTrustStore(String persistentKeyStore,String certName,X509Certificate cert) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException, SignatureException {



		//new keystore
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		char[] pass=new char[]{'c','a','m','b','i','a','r'};
		keyStore.load(null,pass );
		keyStore.store(new FileOutputStream(new File(persistentKeyStore)), pass);
		
	
		
		//store cert
		keyStore.setCertificateEntry(certName, cert);
	
		keyStore.store(new FileOutputStream(new File(persistentKeyStore)), pass);
		for (int i = 0; i < pass.length; i++) {
			pass[i]='\0';		
		}
		return cert;
	}

	private static X509Certificate createKeyStore(String persistentKeyStore,String certName,String keyName) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalStateException, SignatureException {



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
		keyStore.setCertificateEntry(certName, cert);
		java.security.cert.Certificate[] chain = {cert};
		keyStore.setKeyEntry(keyName, keyPair.getPrivate(),pass,chain);

		keyStore.store(new FileOutputStream(new File(persistentKeyStore)), pass);
		for (int i = 0; i < pass.length; i++) {
			pass[i]='\0';		
		}
		return cert;
	}

	
	
	public static void main(String[] args) {
		
		java.security.Security.addProvider(new BouncyCastleProvider());

		
		
		String strClientCertsDir="bcclientcerts";
		String strServerCertsDir="bcservercerts";
		String strClientKeyStore=strClientCertsDir+"/"+"clientkeystore";
		String strServerKeyStore=strServerCertsDir+"/"+"serverkeystore";
		String strClientTrustStore=strClientCertsDir+"/"+"clienttruststore";
		String strServerTrustStore=strServerCertsDir+"/"+"servertruststore";
		
		try {
			X509Certificate serverCert = createKeyStore(strServerKeyStore,"ServerCert","ServerCertKey");
			X509Certificate clientCert = createKeyStore(strClientKeyStore,"ClientCert","ClientCertKey");
			createTrustStore(strClientTrustStore, "ServerCert", serverCert);
			createTrustStore(strServerTrustStore, "ClientCert", clientCert);
		} catch (InvalidKeyException | KeyStoreException | NoSuchAlgorithmException | CertificateException
				| NoSuchProviderException | InvalidAlgorithmParameterException | IllegalStateException
				| SignatureException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("Done!");
		
	}
	
	
}
