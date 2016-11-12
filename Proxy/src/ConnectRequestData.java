import javax.net.ssl.SSLSocket;

public class ConnectRequestData {

	private SSLSocket socket;
	private String remoteHost;
	private int port;

	public ConnectRequestData(SSLSocket socket, String remoteHost, int port) {
		this.socket = socket;
		this.remoteHost = remoteHost;
		this.port = port;
	}

	public SSLSocket getSocket() {
		return socket;
	}

	public String getRemoteHost() {
		return remoteHost;
	}

	public int getPort() {
		return port;
	}

}
