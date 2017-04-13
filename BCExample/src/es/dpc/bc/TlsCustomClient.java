package es.dpc.bc;

import java.io.IOException;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class TlsCustomClient  extends DefaultTlsClient{

	private  TlsSession session;
	private X509Certificate certificate;

	private  KeyStore keyStore;
	private KeyStore trustStore;

	public TlsCustomClient( TlsSession session,X509Certificate certificate, KeyStore keyStore,KeyStore trustStore) {
		this.session=session;
		this.certificate=certificate;
		this.keyStore=keyStore;
		this.trustStore=trustStore;
	}
	public int[] getCipherSuites()
	{
		return new int[]
				{
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
						CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
						CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
						CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
				};
	}

	public TlsSession getSessionToResume()
	{
		return this.session;
	}

	public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
	{
		PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
		out.println("TLS client raised alert: " + AlertLevel.getText(alertLevel)
		+ ", " + AlertDescription.getText(alertDescription));
		if (message != null)
		{
			out.println("> " + message);
		}
		if (cause != null)
		{
			cause.printStackTrace(out);
		}
	}

	public void notifyAlertReceived(short alertLevel, short alertDescription)
	{
		PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
		out.println("TLS client received alert: " + AlertLevel.getText(alertLevel)
		+ ", " + AlertDescription.getText(alertDescription));
	}

	public Hashtable getClientExtensions() throws IOException
	{
		Hashtable clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(super.getClientExtensions());
		TlsExtensionsUtils.addEncryptThenMACExtension(clientExtensions);
		TlsExtensionsUtils.addExtendedMasterSecretExtension(clientExtensions);
		{
			/*
			 * NOTE: If you are copying test code, do not blindly set these extensions in your own client.
			 */
			TlsExtensionsUtils.addMaxFragmentLengthExtension(clientExtensions, MaxFragmentLength.pow2_9);
			TlsExtensionsUtils.addPaddingExtension(clientExtensions, context.getSecureRandom().nextInt(16));
			TlsExtensionsUtils.addTruncatedHMacExtension(clientExtensions);
		}
		return clientExtensions;
	}


	public void notifyServerVersion(ProtocolVersion serverVersion) throws IOException
	{
		super.notifyServerVersion(serverVersion);

		System.out.println("TLS client negotiated " + serverVersion);
	}

	public TlsAuthentication getAuthentication()
			throws IOException
	{
		return new TlsAuthentication()
		{
			public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate)
					throws IOException
			{
				try {
					boolean valid=false;
					Certificate[] chain = serverCertificate.getCertificateList();
					Certificate certificate0 = serverCertificate.getCertificateAt(0);
					PublicKey publicKey = new X509CertificateObject(certificate0).getPublicKey();
					Enumeration<String> aliases = trustStore.aliases();
					while (aliases.hasMoreElements() && !valid) {
						String alias = (String) aliases.nextElement();
						java.security.cert.Certificate certificateTrusted = trustStore.getCertificate(alias);

						try {
							// Try to verify certificate signature with its store publics key
							certificateTrusted.verify(publicKey);
							valid=true;
						} catch (SignatureException sigEx) {
							// Invalid signature --> not self-signed
							//do nothing
						} catch (InvalidKeyException keyEx) {
							// Invalid key --> not self-signed
							// do nothing
						} catch (CertificateException e) {
							// TODO Auto-generated catch block
							// do nothing
						} catch (NoSuchAlgorithmException e) {
							// TODO Auto-generated catch block
							// do nothing
						} catch (NoSuchProviderException e) {
							// TODO Auto-generated catch block
							// do nothing
						}
					}
					if(!valid)
						throw new IOException("Cert not found in the TrustStore, Killing comunication");
				} catch (KeyStoreException e) {
					e.printStackTrace();
					throw new IOException(e);
				} catch (CertificateParsingException e1) {
					e1.printStackTrace();
					throw new IOException(e1);
				}
			}

			public TlsCredentials getClientCredentials(
					CertificateRequest certificateRequest) throws IOException {
				try {
					char[] pass=new char[]{'c','a','m','b','i','a','r'};
					PrivateKey privateKey=(PrivateKey)keyStore.getKey("ClientCertKey", pass);
					for (int i = 0; i < pass.length; i++) {
						pass[i]='\0';		
					}
					byte[] encoding = TlsCustomClient.this.certificate.getEncoded();		        	
					org.bouncycastle.crypto.tls.Certificate bcCert = new  org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[]{ org.bouncycastle.asn1.x509.Certificate.getInstance(encoding)});
					AsymmetricKeyParameter createKey = PrivateKeyFactory.createKey(privateKey.getEncoded());

					SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
					if (supportedSignatureAlgorithms != null)
					{
						for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
						{
							SignatureAndHashAlgorithm alg = (SignatureAndHashAlgorithm)
									supportedSignatureAlgorithms.elementAt(i);
							if (alg.getSignature() == SignatureAlgorithm.ecdsa)
							{
								signatureAndHashAlgorithm = alg;
								break;
							}
						}

						if (signatureAndHashAlgorithm == null)
						{
							return null;
						}
					}



					SubjectPublicKeyInfo keyInfo = bcCert.getCertificateAt(0).getSubjectPublicKeyInfo();

					AsymmetricKeyParameter key=  PublicKeyFactory.createKey(keyInfo);


					return  new DefaultTlsSignerCredentials(context, bcCert,createKey,signatureAndHashAlgorithm);
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch(Exception e){
					e.printStackTrace();
				}
				return null;	
			}
		};
	}

	public void notifyHandshakeComplete() throws IOException
	{
		super.notifyHandshakeComplete();

		TlsSession newSession = context.getResumableSession();
		if (newSession != null)
		{
			byte[] newSessionID = newSession.getSessionID();
			String hex = Hex.toHexString(newSessionID);

			if (this.session != null && Arrays.areEqual(this.session.getSessionID(), newSessionID))
			{
				System.out.println("Resumed session: " + hex);
			}
			else
			{
				System.out.println("Established session: " + hex);
			}

			this.session = newSession;
		}
	}

}
