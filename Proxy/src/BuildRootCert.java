import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

public class BuildRootCert {

	public static void main(String[] args) throws KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, SignatureException, IOException {

		LinkedHashMap<String, PrivateKey> aliasesToKeys = new LinkedHashMap<>();
		LinkedHashMap<String, Certificate[]> aliasesToCerts = new LinkedHashMap<>();
		
		String filePath = args[0];
		String password = args[1];
		CertificateKeyPair pair = null;
		List<Certificate> certificateChain = new ArrayList<>();
		for (int i = 2; i < args.length; i++) {
			String[] argParts = args[i].split(",");
			String alias = argParts[0];
			String canonicalName = argParts[1];
			if (pair == null) {
				pair = buildCertificate(canonicalName);
			} else {
				pair = buildCertificate(canonicalName, pair.getCertificate(), pair.getKey());
			}
			aliasesToKeys.put(alias, pair.getKey());
			certificateChain.add(0, pair.getCertificate());
			Certificate[] chain = new Certificate[certificateChain.size()];
			chain = certificateChain.toArray(chain);
			aliasesToCerts.put(alias, chain);
		}
		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, null);
		Set<String> aliasesSet = aliasesToKeys.keySet();
		for (String alias : aliasesSet) {
			PrivateKey privateKey = aliasesToKeys.get(alias);
			ks.setKeyEntry(alias, privateKey, password.toCharArray(), aliasesToCerts.get(alias));
		}
		try (FileOutputStream output = new FileOutputStream(filePath)) {
			ks.store(output, password.toCharArray());
		}
		
	}

	private static CertificateKeyPair buildCertificate(String canonicalName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, SignatureException, IOException {
		CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
		keyGen.generate(2048);
		PrivateKey selfSignedPrivateKey = keyGen.getPrivateKey();

		X509Certificate selfSignedCertificate = keyGen.getSelfCertificate(new X500Name("CN=" + canonicalName), (long) 365 * 24 * 60 * 60);
		selfSignedCertificate = CommonCertificateUtilities.buildSignedCertificate(selfSignedCertificate, selfSignedCertificate, selfSignedPrivateKey, false);
		CertificateKeyPair pair = new CertificateKeyPair(selfSignedCertificate, selfSignedPrivateKey);
		return pair;
	}
	
	private static CertificateKeyPair buildCertificate(String canonicalName, X509Certificate issuerCertificate, PrivateKey issuerPrivateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, SignatureException, IOException {
		CertAndKeyGen keyGen1 = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
		keyGen1.generate(2048);
		PrivateKey privateKey = keyGen1.getPrivateKey();

		X509Certificate certificate = keyGen1.getSelfCertificate(new X500Name("CN=" + canonicalName), (long) 365 * 24 * 60 * 60);
		certificate = CommonCertificateUtilities.buildSignedCertificate(certificate, issuerCertificate, issuerPrivateKey, false);
		CertificateKeyPair pair = new CertificateKeyPair(certificate, privateKey);
		return pair;
	}

}
