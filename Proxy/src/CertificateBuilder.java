import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

/**
 * SSL Certificates Builder.
 * @author Juliano
 */
public class CertificateBuilder {
	
	private char[] password;
	private KeyStore keystore = null;
	private CertificateKeyPair[] chainCertificatesKeysPairs = null;
	private CertificateKeyPair signerCertificate = null;

	/**
	 * Constructor.
	 * @param keystoreFile File containing the keystore in JKS format.
	 * @param password Password of the keystore file.
	 * @param entriesAliases Aliases of the parent certificates which will be used to sign the generated certs.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 */
	public CertificateBuilder(File keystoreFile, char[] password, String[] entriesAliases) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, IOException, InvalidKeyException, NoSuchProviderException, SignatureException {
		this.password = password;
		loadCertificates(keystoreFile, password, entriesAliases);
	}
	
	/**
	 * Build a SSL Certificate for the specified host name.
	 * The new certificate will be stored into the loaded keystore in memory,
	 * but it won't be persisted on file.
	 * @param canonicalName Host name.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws CertificateException
	 * @throws SignatureException
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws IOException
	 */
	public void buildLeafCertificate(String canonicalName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException, SignatureException, KeyStoreException, UnrecoverableKeyException, IOException {
		
		CertAndKeyGen keyGen = new CertAndKeyGen("RSA", "SHA256WithRSA", null);
		keyGen.generate(2048);
		PrivateKey leafPrivateKey = keyGen.getPrivateKey();

		X509Certificate leafCertificate = keyGen.getSelfCertificate(new X500Name("CN=" + canonicalName), (long) 365 * 24 * 60 * 60);
		leafCertificate = CommonCertificateUtilities.buildSignedCertificate(leafCertificate, signerCertificate.getCertificate(), signerCertificate.getKey(), true);
		Certificate[] certificateChain = new Certificate[chainCertificatesKeysPairs.length + 1];
		certificateChain[0] = leafCertificate;
		for (int i = 1; i <= chainCertificatesKeysPairs.length; i++) {
			certificateChain[i] = chainCertificatesKeysPairs[chainCertificatesKeysPairs.length - i].getCertificate();
		}
		keystore.setKeyEntry(canonicalName, leafPrivateKey, password, certificateChain);
		
	}
	
	/**
	 * Returns the loaded keystore.
	 * @return The loaded keystore.
	 */
	public KeyStore getKeyStore() {
		return keystore;
	}
	
	/**
	 * Load the certificates and private keys corresponding to the specified aliases from the
	 * keystore.
	 * @param keystoreFile File containing the keystore in JKS format.
	 * @param password Password of the keystore file.
	 * @param entriesAliases Aliases of the parent certificates which will be used to sign the generated certs.
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 */
	private void loadCertificates(File keystoreFile, char[] password, String[] entriesAliases) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException {

		chainCertificatesKeysPairs = new CertificateKeyPair[entriesAliases.length];
		keystore = KeyStore.getInstance("JKS");
		try (FileInputStream input = new FileInputStream(keystoreFile)) {
			keystore.load(input, password);
		}
		
		for (int i = 0; i < entriesAliases.length; i++) {
		
			String entryAlias = entriesAliases[i];
			if (keystore.containsAlias(entryAlias) && keystore.isKeyEntry(entryAlias)) {
				Key key = keystore.getKey(entryAlias, password);
				Certificate certificate = keystore.getCertificate(entriesAliases[i]);
				if (key instanceof PrivateKey && certificate instanceof X509Certificate) {
					CertificateKeyPair pair = new CertificateKeyPair((X509Certificate) certificate, (PrivateKey) key);
					chainCertificatesKeysPairs[i] = pair;
				} else {
					throw new IllegalArgumentException();
				}
			} else {
				throw new IllegalArgumentException();
			}
		
		}
		
		if (chainCertificatesKeysPairs.length > 0) {
			signerCertificate = chainCertificatesKeysPairs[chainCertificatesKeysPairs.length - 1];
			if (signerCertificate == null) {
				// TODO
			}
		}
		
	}

}