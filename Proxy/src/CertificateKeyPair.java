import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class CertificateKeyPair {

	private X509Certificate certificate;
	private PrivateKey key;
	
	public CertificateKeyPair(X509Certificate certificate, PrivateKey key) {
		this.certificate = certificate;
		this.key = key;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public PrivateKey getKey() {
		return key;
	}

}
