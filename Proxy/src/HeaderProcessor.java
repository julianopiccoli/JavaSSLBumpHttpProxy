import java.io.UnsupportedEncodingException;
import java.net.ProtocolException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Processor for the HTTP protocol headers.
 * @author Juliano
 */
public class HeaderProcessor {

	private final static String LINE_BREAK = "\r\n";
	
	private Map<String, List<String>> headers;
	private String content;
	
	private boolean responseMessage;
	
	private RequestHeader requestHeader;
	private ResponseHeader responseHeader;
	
	private Long contentLength;
	private boolean chunkedEncoded;
	private boolean keepConnectionAlive;
	
	private byte[] bodyData;

	private boolean gotMainHeader;
	private boolean firstPass;
	
	/**
	 * Constructor.
	 * @param responseMessage If true, the processor assumes that the header being
	 * processed is part of a HTTP response. Otherwise, it treats the message as a
	 * HTTP request. 
	 */
	public HeaderProcessor(boolean responseMessage) {
		this.responseMessage = responseMessage;
		headers = new HashMap<>();
		content = "";
		firstPass = true;
	}
	
	/**
	 * Process data received from the network.
	 * @param data Buffer holding the received data.
	 * @param offset Offset from where to start reading the data.
	 * @param length Length of the data segment
	 * @return True if, and only if, the full HTTP header was processed.
	 * @throws ProtocolException If the processed content violates the HTTP protocol.
	 */
	public boolean processInputData(final byte[] data, final int offset, final int length) throws ProtocolException {
		
		int bytePosition = 0;
		int newDataOffset = content.length();
		try {
			content = content.concat(new String(data, offset, length, "US-ASCII"));
		} catch (UnsupportedEncodingException e) {
			// Ignore this block. According to the J2SE specs, every implementation of the
			// Java platform is required to support the US-ASCII charset (http://docs.oracle.com/javase/1.5.0/docs/api/java/nio/charset/Charset.html).
			// Therefore, this exception will never occur.
		}
		int lineBreakIndex = content.indexOf(LINE_BREAK);
		while(lineBreakIndex >= 0) {
			bytePosition += lineBreakIndex + 2;
			if (lineBreakIndex == 0 && !firstPass) {
				parseFields();
				int bodyDataOffset = bytePosition - newDataOffset;
				storeBodyData(data, offset + bodyDataOffset, length - bodyDataOffset);
				return true;
			}
			firstPass = false;
			String header = content.substring(0, lineBreakIndex);
			if (!header.isEmpty()) {
				if (!gotMainHeader) {
					parseMainHeader(header);
					gotMainHeader = true;
				} else {
					parseHeader(header);
				}
			}
			content = content.substring(lineBreakIndex + LINE_BREAK.length());
			lineBreakIndex = content.indexOf(LINE_BREAK);
		}
		return false;
		
	}
	
	/**
	 * Returns wheter this processor is operating in response or request mode.
	 * @return True if, and only if, this processor is operating in response mode.
	 */
	public boolean isResponseMode() {
		return responseMessage;
	}
	
	/**
	 * Retrieves the set of headers already processed.
	 * @return The set of headers already processed.
	 */
	public Map<String, List<String>> getHeaders() {
		return headers;
	}
	
	/**
	 * Get the processed RequestHeader object. If this processor is operating
	 * in response mode, this method will always return null. Otherwise, it will
	 * return a non-null object after the first line of the HTTP header is fully
	 * processed.
	 * @return The main header of the processed request.
	 */
	public RequestHeader getRequestHeader() {
		return requestHeader;
	}

	/**
	 * Get the processed ResponseHeader object. If this processor is not operating
	 * in response mode, this method will always return null. Otherwise, it will
	 * return a non-null object after the first line of the HTTP header is fully
	 * processed.
	 * @return The main header of the processed response.
	 */
	public ResponseHeader getResponseHeader() {
		return responseHeader;
	}
	
	/**
	 * Get the Content-Length of the message body. If the Content-Length
	 * field was not specified in the HTTP header, this method will return
	 * null.
	 * @return The content-length of the message body if, and only if, the
	 * Content-Length field have been specified in the HTTP header.
	 */
	public Long getContentLength() {
		return contentLength;
	}
	
	/**
	 * Get the chunked encoding flag. Is will be true if, and only
	 * if, the Transfer-Encoding field have been specified with
	 * the value "chunked" in the HTTP header.
	 * @return The chunked encoding flag.
	 */
	public boolean isChunkedEncoded() {
		return chunkedEncoded;
	}
	
	/**
	 * Get the keep connection alive flag. It will be true if, and
	 * only if, the Connection or Proxy-Connection field have been
	 * specifieds with the value "keep-alive" in the HTTP header. 
	 * @return The keep connection alive flag.
	 */
	public boolean isKeepConnectionAlive() {
		return keepConnectionAlive;
	}
	
	/**
	 * Get the stored body message data. While processing the HTTP header, part of
	 * the message body may be passed in the method processInput along with the header
	 * content. This message body part will be stored in a temporary buffer which can
	 * be obtained using this method.
	 * @return The stored message body data.
	 */
	public byte[] getBodyData() {
		return bodyData;
	}
	
	private void parseMainHeader(String header) throws ProtocolException {
		if (responseMessage) {
			int index1 = header.indexOf(" ");
			int index2 = header.indexOf(" ", index1 + 1);
			if (index1 > 0 && index2 > 0) {
				String token1 = header.substring(0, index1);
				String token2 = header.substring(index1 + 1, index2);
				String token3 = header.substring(index2 + 1);
				try {
					responseHeader = new ResponseHeader();
					responseHeader.setProtocol(token1);
					responseHeader.setStatusCode(Integer.parseInt(token2));
					responseHeader.setStatusText(token3);
				} catch (NumberFormatException e) {
					throw new ProtocolException();
				}
			} else {
				throw new ProtocolException();
			}
		} else {
			int index1 = header.indexOf(" ");
			int index2 = header.lastIndexOf(" ");
			if (index1 > 0 && index2 > 0) {
				String token1 = header.substring(0, index1);
				String token2 = header.substring(index1 + 1, index2);
				String token3 = header.substring(index2 + 1);
				requestHeader = new RequestHeader();
				requestHeader.setMethod(token1);
				requestHeader.setResource(token2);
				requestHeader.setProtocol(token3);
			} else {
				throw new ProtocolException();
			}
		}
	}
	
	private void parseHeader(String header) throws ProtocolException {
		int index = header.indexOf(":");
		if (index > 0) {
			String headerName = header.substring(0, index);
			String headerValue = header.substring(index + 1);
			headerName = headerName.trim();
			headerValue = headerValue.trim();
			List<String> values = headers.get(headerName);
			if (values == null) {
				values = new ArrayList<String>();
				headers.put(headerName, values);
			}
			values.add(headerValue);
		} else {
			throw new ProtocolException();
		}
	}
	
	private void storeBodyData(final byte[] data, int offset, int length) {
		bodyData = new byte[length];
		System.arraycopy(data, offset, bodyData, 0, length);
	}
	
	private void parseFields() {
		List<String> contentLengthValues = headers.get("Content-Length");
		if (contentLengthValues != null && contentLengthValues.size() == 1) {
			try {
				contentLength = Long.parseLong(contentLengthValues.get(0));
			} catch (NumberFormatException e) {
				//
			}
		}
		List<String> transferEncodingValues = headers.get("Transfer-Encoding");
		if (transferEncodingValues != null && transferEncodingValues.size() == 1 && transferEncodingValues.get(0).equalsIgnoreCase("chunked")) {
			chunkedEncoded = true;
		}
		List<String> connectionValues = headers.get("Connection");
		if (connectionValues != null && connectionValues.size() == 1 && connectionValues.get(0).equalsIgnoreCase("keep-alive")) {
			keepConnectionAlive = true;
		}
		List<String> proxyConnectionValues = headers.get("Proxy-Connection");
		if (proxyConnectionValues != null && proxyConnectionValues.size() == 1 && proxyConnectionValues.get(0).equalsIgnoreCase("keep-alive")) {
			keepConnectionAlive = true;
		}
	}
	
}
