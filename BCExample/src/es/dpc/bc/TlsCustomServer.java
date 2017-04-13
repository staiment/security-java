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
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Arrays;


public class TlsCustomServer  extends DefaultTlsServer {
	
	private  X509Certificate certificate;
	
	private KeyStore keyStore ;
	
	private KeyStore trustStore;
	
	public TlsCustomServer( X509Certificate certificate,KeyStore keyStore,KeyStore trustStore ) {
		this.certificate=certificate;
		this.keyStore=keyStore;
		this.trustStore=trustStore;
	}
	 protected int[] getCipherSuites()
	    {
	        return new int[]
	        {
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
	            CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
	        };
	    }

	@Override
	public TlsCredentials getCredentials() throws IOException {
		try {
			char[] pass=new char[]{'c','a','m','b','i','a','r'};
			PrivateKey privateKey=(PrivateKey)keyStore.getKey("ServerCertKey", pass);
			for (int i = 0; i < pass.length; i++) {
				pass[i]='\0';		
			}
			byte[] encoding = certificate.getEncoded();		        	
			final Certificate bcCert = new Certificate(new org.bouncycastle.asn1.x509.Certificate[]{ org.bouncycastle.asn1.x509.Certificate.getInstance(encoding)});
			AsymmetricKeyParameter createKey = PrivateKeyFactory.createKey(privateKey.getEncoded());
			
			 /*
	         * TODO Note that this code fails to provide default value for the client supported
	         * algorithms if it wasn't sent.
	         */
	     
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
			
	       ECPublicKeyParameters validateECPublicKey = TlsECCUtils.validateECPublicKey((ECPublicKeyParameters) key);
	       
			return  new DefaultTlsSignerCredentials(context, bcCert,createKey,signatureAndHashAlgorithm);
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch(Exception e){
			e.printStackTrace();
		}
    	return null;			
    }

    public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate)
        throws IOException
    {
    	try {
			boolean valid=false;
			org.bouncycastle.asn1.x509.Certificate certificate0 = clientCertificate.getCertificateAt(0);
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

	
	@Override
    public CertificateRequest getCertificateRequest() throws IOException {
    	// TODO Auto-generated method stub
    	short[] certTypes={ClientCertificateType.ecdsa_sign};
    	   Vector serverSigAlgs = null;
           if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion))
           {
               serverSigAlgs = TlsUtils.getDefaultSupportedSignatureAlgorithms();
           }

           Vector certificateAuthorities = new Vector();
    	return new CertificateRequest(certTypes, serverSigAlgs, certificateAuthorities);
    }
	
	public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause)
    {
        PrintStream out = (alertLevel == AlertLevel.fatal) ? System.err : System.out;
        out.println("TLS server raised alert: " + AlertLevel.getText(alertLevel)
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
        out.println("TLS server received alert: " + AlertLevel.getText(alertLevel)
            + ", " + AlertDescription.getText(alertDescription));
    }

//    protected int[] getCipherSuites()
//    {
//        return Arrays.concatenate(super.getCipherSuites(),
//            new int[]
//            {
//                CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
//            });
//    }

    protected ProtocolVersion getMaximumVersion()
    {
        return ProtocolVersion.TLSv12;
    }

    public ProtocolVersion getServerVersion() throws IOException
    {
        ProtocolVersion serverVersion = super.getServerVersion();

        System.out.println("TLS server negotiated " + serverVersion);

        return serverVersion;
    }
    
    
}
