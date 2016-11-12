import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;


public class HttpProcessor implements Runnable {

	private SSLSocketFactoryCache cache;
	
	private Socket clientSocket;
	private InputStream clientInputStream;
	private OutputStream clientOutputStream;
	
	private Socket remoteHostSocket;
	private InputStream remoteHostInputStream;
	private OutputStream remoteHostOutputStream;
	
	private byte[] buffer;
	
	public HttpProcessor(SSLSocketFactoryCache cache, Socket clientSocket) throws IOException {
		this.cache = cache;
		this.clientSocket = clientSocket;
		clientSocket.setSoTimeout(10000);
		buffer = new byte[1024 * 10];
	}
	
	public void run() {

		try {
			clientInputStream = clientSocket.getInputStream();
			clientOutputStream = clientSocket.getOutputStream();
			boolean useSSL = processConnection(false);
			if (useSSL) {
				processConnection(true);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				clientSocket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
			if (remoteHostSocket != null) {
				try {
					remoteHostSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		
	}
	
	private boolean processConnection(boolean useSSL) throws IOException {

		int readResult = 0;
		
		try {

			while(true) {
			
				boolean headerProcessed = false;
				HeaderProcessor requestHeaderProcessor = new HeaderProcessor(false);
				while(!headerProcessed) {
					readResult = clientInputStream.read(buffer, 0, buffer.length);
					if (readResult > 0) {
						headerProcessed = requestHeaderProcessor.processInputData(buffer, 0, readResult);
					} else {
						throw new ProtocolException();
					}
				}
				
				String resource = null;
				RequestHeader requestHeader = requestHeaderProcessor.getRequestHeader();
				if (requestHeader.getMethod().equalsIgnoreCase("CONNECT")) {
					ConnectRequestData data = processConnectRequest(requestHeader);
					clientSocket = data.getSocket();
					clientSocket.setSoTimeout(10000);
					clientInputStream = clientSocket.getInputStream();
					clientOutputStream = clientSocket.getOutputStream();
					openRemoteSocket(data.getRemoteHost(), data.getPort(), true);
					return true;
				} else {
					if (useSSL) {
						resource = requestHeader.getResource();
					} else {
						if (remoteHostSocket == null) {
							URL url = new URL(requestHeader.getResource());
							String remoteHost = url.getHost();
							int remotePort = url.getPort();
							if (remotePort == -1) {
								remotePort = 80;
							}
							openRemoteSocket(remoteHost, remotePort, false);
							resource = url.getFile();
						} else {
							resource = requestHeader.getResource();
						}
					}
				}
				
				sendRequestHeader(requestHeader.getMethod(), resource, requestHeaderProcessor.getHeaders(), remoteHostOutputStream);
				if (requestHeaderProcessor.getContentLength() != null) {
					sendBody(requestHeaderProcessor.getBodyData(), requestHeaderProcessor.getContentLength(), clientInputStream, remoteHostOutputStream);
				} else if (requestHeaderProcessor.isChunkedEncoded()) {
					sendChunkedBody(requestHeaderProcessor.getBodyData(), clientInputStream, remoteHostOutputStream);
				}
				
				headerProcessed = false;
				HeaderProcessor responseHeaderProcessor = new HeaderProcessor(true);
				while(!headerProcessed) {
					readResult = remoteHostInputStream.read(buffer, 0, buffer.length);
					if (readResult > 0) {
						headerProcessed = responseHeaderProcessor.processInputData(buffer, 0, readResult);
					} else {
						throw new ProtocolException();
					}
				}
				
				sendResponseHeader(responseHeaderProcessor.getResponseHeader(), responseHeaderProcessor.getHeaders(), clientOutputStream);
				if (responseHeaderProcessor.getContentLength() != null) {
					sendBody(responseHeaderProcessor.getBodyData(), responseHeaderProcessor.getContentLength(), remoteHostInputStream, clientOutputStream);
				} else if (responseHeaderProcessor.isChunkedEncoded()) {
					sendChunkedBody(responseHeaderProcessor.getBodyData(), remoteHostInputStream, clientOutputStream);
				} else {
					sendBody(responseHeaderProcessor.getBodyData(), remoteHostInputStream, clientOutputStream);
				}
				
				if (!responseHeaderProcessor.isKeepConnectionAlive()) {
					break;
				}
				
			}
			
		} catch (IOException | InvalidKeyException | UnrecoverableKeyException | KeyManagementException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException | SignatureException | KeyStoreException e) {
			e.printStackTrace();
		}
		
		return false;
		
	}
	
	private void openRemoteSocket(String host, int port, boolean useSSL) throws UnknownHostException, IOException {
		if (remoteHostSocket == null) {
			if (useSSL) {
				SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
				SSLSocket remoteHostSSLSocket = (SSLSocket) factory.createSocket(host, port);
				remoteHostSSLSocket.setUseClientMode(true);
				remoteHostSocket = remoteHostSSLSocket;
			} else {
				remoteHostSocket = new Socket(host, port);
			}
			remoteHostSocket.setSoTimeout(10000);
			remoteHostInputStream = remoteHostSocket.getInputStream();
			remoteHostOutputStream = remoteHostSocket.getOutputStream();
		}
	}
	
	private ConnectRequestData processConnectRequest(RequestHeader header) throws InvalidKeyException, UnrecoverableKeyException, KeyManagementException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, SignatureException, KeyStoreException, IOException {
		SSLSocketFactory factory;
		String resource = header.getResource();
		int hostPortSeparator = resource.indexOf(":");
		if (hostPortSeparator > 0) {
			String host = resource.substring(0, hostPortSeparator);
			String portText = resource.substring(hostPortSeparator + 1);
			int port = Integer.parseInt(portText);
			sendConnectResponse();
			factory = cache.getSocketFactory(host);
			SSLSocket sslSocket = (SSLSocket) factory.createSocket(clientSocket, clientSocket.getInetAddress().getHostAddress(), clientSocket.getPort(), false);
			sslSocket.setUseClientMode(false);
			sslSocket.setWantClientAuth(false);
			ConnectRequestData data = new ConnectRequestData(sslSocket, host, port);
			return data;
		}
		throw new ProtocolException();
	}
	
	private void sendRequestHeader(String method, String resource, Map<String, List<String>> headers, OutputStream outputStream) throws IOException {
		String fullHeader = method + " " + resource + " HTTP/1.1\r\n";
		Set<String> fieldsNamesSet = headers.keySet();
		for (String fieldName : fieldsNamesSet) {
			List<String> values = headers.get(fieldName);
			for (String value : values) {
				if (fieldName.equals("Proxy-Connection")) {
					fullHeader += "Connection: " + value + "\r\n";
				}
				fullHeader += fieldName + ": " + value + "\r\n";
			}
		}
		fullHeader += "\r\n";
		outputStream.write(fullHeader.getBytes("ASCII7"));
	}
	
	private void sendResponseHeader(ResponseHeader responseHeader, Map<String, List<String>> headers, OutputStream outputStream) throws IOException {
		String fullHeader = responseHeader.getProtocol() + " " + responseHeader.getStatusCode() + " " + responseHeader.getStatusText() + "\r\n";
		Set<String> fieldsNamesSet = headers.keySet();
		for (String fieldName : fieldsNamesSet) {
			List<String> values = headers.get(fieldName);
			for (String value : values) {
				if (fieldName.equals("Proxy-Connection")) {
					fullHeader += "Connection: " + value + "\r\n";
				}
				fullHeader += fieldName + ": " + value + "\r\n";
			}
		}
		fullHeader += "\r\n";
		outputStream.write(fullHeader.getBytes("ASCII7"));
	}
	
	private void sendChunkedBody(byte[] bodyData, InputStream inputStream, OutputStream outputStream) throws IOException {
		ChunkedStreamProcessor chunkedProcessor = new ChunkedStreamProcessor();
		int streamEndPosition = -1;
		if (bodyData != null && bodyData.length > 0) {
			streamEndPosition = chunkedProcessor.process(bodyData, 0, bodyData.length);
			outputStream.write(bodyData);
		}
		if (streamEndPosition < 0) {
			int readResult = inputStream.read(buffer);
			while(readResult > 0) {
				streamEndPosition = chunkedProcessor.process(buffer, 0, readResult);
				if (streamEndPosition < 0) {
					outputStream.write(buffer, 0, readResult);
					readResult = inputStream.read(buffer);
				} else {
					outputStream.write(buffer, 0, readResult);
					break;
				}
			}
		}
	}
	
	private void sendBody(byte[] bodyData, long contentLength, InputStream inputStream, OutputStream outputStream) throws IOException {
		if (bodyData != null && bodyData.length > 0) {
			outputStream.write(bodyData);
			contentLength -= bodyData.length;
		}
		if (contentLength > 0) {
			int transferSize = contentLength > buffer.length ? buffer.length : (int) contentLength;
			int readResult = inputStream.read(buffer, 0, transferSize);
			while(readResult > 0 && contentLength > 0) {
				outputStream.write(buffer, 0, readResult);
				contentLength -= readResult;
				transferSize = contentLength > buffer.length ? buffer.length : (int) contentLength;
				if (transferSize > 0) {
					readResult = inputStream.read(buffer, 0, transferSize);
				}
			}
		}
	}
	
	private void sendBody(byte[] bodyData, InputStream inputStream, OutputStream outputStream) throws IOException {
		if (bodyData != null && bodyData.length > 0) {
			outputStream.write(bodyData);
		}
		int readResult = inputStream.read(buffer, 0, buffer.length);
		while(readResult > 0) {
			outputStream.write(buffer, 0, readResult);
			readResult = inputStream.read(buffer, 0, buffer.length);
		}
	}
	
	private void sendConnectResponse() throws IOException {
		
		OutputStream clientOutputStream = clientSocket.getOutputStream();
		String response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
		byte[] data = response.getBytes("ASCII7");
		clientOutputStream.write(data);
		
	}
	
}
