import java.io.IOException;
import java.net.ProtocolException;
import java.util.HashMap;
import java.util.Map;

/**
 * Processor for chunked-encoded HTTP messages.
 * @author Juliano
 */
public class ChunkedStreamProcessor {
	
	private static final String LINE_BREAK = "\r\n";
	private static final int LINE_BREAK_LENGTH = LINE_BREAK.length();
	
	private String content;
	private long currentChunkSize;
	private boolean skipChunkEndingCRLF;
	private boolean readingChunkData;
	private boolean readingTrailer;
	
	private Map<String, String> trailers;
	
	private int processingOffset;
	private int processingLength;
	
	/**
	 * Constructor.
	 */
	public ChunkedStreamProcessor() {
		content = "";
		currentChunkSize = 0;
		skipChunkEndingCRLF = false;
		readingChunkData = false;
		readingTrailer = false;
		trailers = new HashMap<>();
		processingOffset = 0;
		processingLength = 0;
	}

	/**
	 * Process the specified data.
	 * @param data Buffer holding the data which will be processed.
	 * @param offset Offset from where to start reading the data.
	 * @param length Length of the data segment
	 * @return The position in the specified data buffer where the chunked stream ends. If
	 * the stream end is not found within the supplied data, -1 is returned.
	 * @throws IOException If the processed content violates the chunked transfer coding spec.
	 */
	public int process(final byte[] data, final int offset, final int length) throws IOException {
		
		this.processingOffset = offset;
		this.processingLength = length;

		while(processingLength > 0 && !readingTrailer) {
			if (readingChunkData) {
				processChunkData(data);
			} else {
				int dataOffset = content.length();
				content = content.concat(new String(data, processingOffset, processingLength, "ASCII7"));
				int crlfIndex = content.indexOf(LINE_BREAK);
				if (crlfIndex > 0) {
					Map<String, String> extensions = null;
					String chunkHeader = content.substring(0, crlfIndex);
					String chunkSizeText = chunkHeader;
					int semicolonIndex = chunkHeader.indexOf(';');
					content = "";
					if (semicolonIndex > 0) {
						chunkSizeText = chunkHeader.substring(0, semicolonIndex);
						String chunkExtensions = chunkHeader.substring(semicolonIndex + 1);
						extensions = parseExtensions(chunkExtensions);
						// TODO Do something with extensions
					}
					try {
						currentChunkSize = Long.parseLong(chunkSizeText, 16);
					} catch (NumberFormatException e) {
						throw new ProtocolException();
					}
					int increment = (crlfIndex + LINE_BREAK_LENGTH - dataOffset);
					processingOffset = processingOffset + increment;
					processingLength = processingLength - increment;
					if (currentChunkSize > 0) {
						processChunkData(data);
					} else {
						readingTrailer = true;
					}
				} else if (crlfIndex == 0 && skipChunkEndingCRLF) {
					content = "";
					int increment = (crlfIndex + LINE_BREAK_LENGTH - dataOffset);
					processingOffset = processingOffset + increment;
					processingLength = processingLength - increment;
					skipChunkEndingCRLF = false;
				} else {
					break;
				}
			}
		}
		
		if (readingTrailer) {
			int dataOffset = content.length();
			content = content.concat(new String(data, processingOffset, processingLength, "ASCII7"));
			int trailerEnd = processTrailer();
			if (trailerEnd > 0) {
				return processingOffset + (trailerEnd - dataOffset);
			}
		}
		
		return -1;
		
	}
	
	/**
	 * Parse the chunk extensions, if any.
	 * @param chunkExtensions String containing a sequence of chunk extensions.
	 * @return A Map of the chunk extensions found.
	 */
	private Map<String, String> parseExtensions(String chunkExtensions) {
		Map<String, String> extensions = new HashMap<>();
		String[] tokens = chunkExtensions.split(";");
		for (String token : tokens) {
			int equalSignIndex = token.indexOf('=');
			if (equalSignIndex > 0) {
				String extensionName = token.substring(0, equalSignIndex);
				String value = token.substring(equalSignIndex + 1);
				extensions.put(extensionName.trim(), value.trim());
			} else {
				extensions.put(token.trim(), null);
			}
		}
		return extensions;
	}
	
	/**
	 * Processes part of the chunk data.
	 * @param data Buffer holding part of the chunk data.
	 */
	private void processChunkData(byte[] data) {
		if (currentChunkSize > processingLength) {
			// TODO Do something with data
			currentChunkSize -= processingLength;
			processingOffset += processingLength;
			processingLength = 0;
			readingChunkData = true;
		} else {
			// TODO Do something with data
			processingOffset += (int) currentChunkSize;
			processingLength -= (int) currentChunkSize;
			currentChunkSize = 0;
			skipChunkEndingCRLF = true;
			readingChunkData = false;
		}
	}
	
	/**
	 * Process the message trailer.
	 * @return The position within the buffered content where the trailer ends.
	 * If the buffered content does not contains the end of the chunked stream,
	 * -1 is returned.
	 * @throws ProtocolException If the processed content violates the chunked transfer coding spec.
	 */
	private int processTrailer() throws ProtocolException {
		int processedLength = 0;
		int lineBreakIndex = content.indexOf(LINE_BREAK);
		while(lineBreakIndex > 0) {
			String trailer = content.substring(0, lineBreakIndex);
			content = content.substring(lineBreakIndex + LINE_BREAK_LENGTH);
			processedLength += lineBreakIndex + LINE_BREAK_LENGTH;
			int delimiterIndex = trailer.indexOf(":");
			if (delimiterIndex > 0) {
				String name = trailer.substring(0, delimiterIndex);
				String value = trailer.substring(delimiterIndex + 1);
				trailers.put(name.trim(), value.trim());
				lineBreakIndex = content.indexOf(LINE_BREAK);
			} else {
				throw new ProtocolException();
			}
		}
		if (lineBreakIndex == 0) {
			processedLength += 2;
			return processedLength;
		}
		return -1;
	}
	
}
