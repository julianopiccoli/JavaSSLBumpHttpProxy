import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public class Proxy extends Thread {

	private ServerSocket serverSocket;
	private SSLSocketFactoryCache cache;
	
	private Executor executor;

	public Proxy(int port, File keystoreFile, char[] password, String[] entriesAliases) throws IOException, InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, NoSuchProviderException, SignatureException {
		serverSocket = new ServerSocket(port);
		cache = new SSLSocketFactoryCache(keystoreFile, password, entriesAliases);
		executor = Executors.newCachedThreadPool();
	}
	
	public void run() {
		try {
			while(true) {
				Socket socket = serverSocket.accept();
				HttpProcessor processor = new HttpProcessor(cache, socket);
				executor.execute(processor);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) throws InvalidKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, NoSuchProviderException, SignatureException, IOException, InterruptedException {
		
		File keystoreFile = new File(args[0]);
		String keystorePassword = args[1];
		String[] entriesAliases = new String[args.length - 2];
		for (int i = 2; i < args.length; i++) {
			entriesAliases[i - 2] = args[i];
		}
		Proxy proxy = new Proxy(3128, keystoreFile, keystorePassword.toCharArray(), entriesAliases);
		proxy.start();
		proxy.join();
		
	}
	
}
