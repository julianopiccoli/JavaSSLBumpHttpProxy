import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Collection of certificate related utilities methods.
 * @author Juliano
 */
public class CommonCertificateUtilities {

	/**
	 * Builds a X509Certificate signed with the specified issuerCertificate. The new
	 * certificate is built using info from the supplied self-signed certificate.
	 * @param certificate Self-signed certificate which will be rebuilt and signed with the supplied issuer certificate.
	 * @param issuerCertificate The issuer certificate which will be used to sign the new certificate.
	 * @param issuerPrivateKey The corresponding private key of the issuer certificate.
	 * @param leafCert If false, the generated certificate will be able to sign other certificates.
	 * @return The newly built signed certificate.
	 * @throws IOException 
	 * @throws CertificateException 
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	static X509Certificate buildSignedCertificate(X509Certificate certificate, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey, boolean leafCert) throws CertificateException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		
		Principal issuerSubjectDN = issuerCertificate.getSubjectDN();
		String issuerSigAlgName = issuerCertificate.getSigAlgName();

		byte[] certificateData = certificate.getTBSCertificate();
		X509CertInfo info = new X509CertInfo(certificateData);
		info.set(X509CertInfo.ISSUER, (X500Name) issuerSubjectDN);

		if (!leafCert) {
			CertificateExtensions extensions = new CertificateExtensions();
			BasicConstraintsExtension basicConstraintsExtension = new BasicConstraintsExtension(true, -1);
			extensions.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(false, basicConstraintsExtension.getExtensionValue()));
			info.set(X509CertInfo.EXTENSIONS, extensions);
		}

		X509CertImpl signedCertificate = new X509CertImpl(info);
		signedCertificate.sign(issuerPrivateKey, issuerSigAlgName);

		return signedCertificate;
		
	}
	
}
