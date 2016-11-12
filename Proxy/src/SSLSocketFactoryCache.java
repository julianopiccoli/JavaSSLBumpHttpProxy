import java.io.File;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

/**
 * Cache of SSLSocketFactories.
 * @author Juliano
 */
public class SSLSocketFactoryCache {

	private char[] password;
	private HashMap<String, SSLSocketFactory> factoriesTable;
	private CertificateBuilder builder;

	/**
	 * Construtor.
	 * @param keystoreFile File containing the keystore in JKS format.
	 * @param password Password of the keystore file.
	 * @param entriesAliases Aliases of the parent certificates which will be used to sign the generated certs.
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 * @throws NoSuchProviderException
	 * @throws SignatureException
	 * @throws IOException
	 */
	public SSLSocketFactoryCache(File keystoreFile, char[] password, String[] entriesAliases) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, NoSuchProviderException, SignatureException, IOException {
		this.password = password;
		factoriesTable = new HashMap<>();
		builder = new CertificateBuilder(keystoreFile, password, entriesAliases);
	}
	
	/**
	 * Get the SSLSocketFactory object corresponding to the supplied hostname. The SSL sockets created by the returned factory,
	 * when configured to operate in server mode, will send a SSL certificate which has the specified hostname as its Canonical Name
	 * in the handshake process.
	 * @param host Host name.
	 * @return The corresponding SSLSocketFactory.
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws CertificateException
	 * @throws SignatureException
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws UnrecoverableKeyException
	 * @throws KeyManagementException
	 */
	public synchronized SSLSocketFactory getSocketFactory(String host) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
		SSLSocketFactory factory = factoriesTable.get(host);
		if (factory == null) {
			SSLContext context = SSLContext.getInstance("SSLv3");
			builder.buildLeafCertificate(host);
			KeyStore keystore = builder.getKeyStore();
			KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			kmf.init(keystore, password);
			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(keystore);
			List<KeyManager> keyManagersList = new LinkedList<KeyManager>();
			KeyManager[] originalKeyManagers = kmf.getKeyManagers();
			for (KeyManager originalKeyManager : originalKeyManagers) {
				if (originalKeyManager instanceof X509KeyManager) {
					keyManagersList.add(new CustomX509KeyManager((X509KeyManager) originalKeyManager, host));
				}
			}
			context.init(keyManagersList.toArray(new KeyManager[keyManagersList.size()]), tmf.getTrustManagers(), null);
			factory = context.getSocketFactory();
			factoriesTable.put(host, factory);
		}
		return factory;
	}

	private class CustomX509KeyManager implements X509KeyManager {
		
		private X509KeyManager originalKeyManager;
		private String alias;

		private CustomX509KeyManager(X509KeyManager originalKeyManager, String alias) {
			this.originalKeyManager = originalKeyManager;
			this.alias = alias;
		}
		
		@Override
		public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
			return alias;
		}

		@Override
		public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
			return alias;
		}

		@Override
		public X509Certificate[] getCertificateChain(String alias) {
			return originalKeyManager.getCertificateChain(alias);
		}

		@Override
		public String[] getClientAliases(String keyType, Principal[] issuers) {
			return originalKeyManager.getClientAliases(keyType, issuers);
		}

		@Override
		public PrivateKey getPrivateKey(String alias) {
			return originalKeyManager.getPrivateKey(alias);
		}

		@Override
		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return originalKeyManager.getServerAliases(keyType, issuers);
		}
		
	}
	
}
