import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicLong;

public class KeyManager {

	private AtomicLong currentKey = null;
	private int keySize = 4; // 4 bytes at minimum as Blowfish supports 32-448 bit key sizes (4 bytes = 32 bit)
	private String ciphertext = null;

	ServerSocket sock;

	long startTimer;
	long endTimer;

	private boolean firstConnect = true;
	private boolean keyFound = false;

	public KeyManager(String[] args) {
		CLIValidation(args);
		acceptConnections();
	}

	public static void main (String[] args) {
		new KeyManager(args);
	}

	private void CLIValidation(String[] args) {
		// CLI Validation
		if (args.length != 3) {
			System.err.println("Usage: java KeyManager <initial-key> <keysize> <ciphertext>");
			System.exit(1);
		}

		// Check if initial key is a long (long is safer for large key values)
		try {currentKey = new AtomicLong(Long.parseLong(args[0]));}
		catch (NumberFormatException e) {
			System.err.println("Argument" + args[0] + " must be an integer.");
			System.exit(1);
		}

		// Check if key-size is an integer and greater than 4. Blowfish only supports 32-448 bit (4 bytes+)
		try {keySize = Math.max(keySize, Integer.parseInt(args[1]));}
		catch (NumberFormatException e) {
			System.err.println("Argument" + args[1] + " must be an integer.");
			System.exit(1);
		}

		ciphertext = args[2];
	}

	private void acceptConnections() {
		// Setup the socket to accept client connections
		try {
			sock = new ServerSocket(0);
			System.out.println("Waiting for connections on " + sock.getLocalPort());

			while (!sock.isClosed()) {
				// now listen for connections
				Socket client = sock.accept();

				// If a client connects and it's the first client then we want to start our timer to see how long it will
				// take to find the key (if we ever do...)
				if (firstConnect) {
					startTimer = System.currentTimeMillis();
					firstConnect = false;
				}

				// Service the connection to the client in a separate thread
				KeyManagerConnection c = new KeyManagerConnection(client, this);
				c.start();
			}
		}
		catch (IOException ioe) {}
	}

	/**
	 * Given a request from a client for work, we need to compose a string to send back to the client
	 * as a mesaage to indicate where their work needs to start and end.
	 *
	 * If the clientChunkSize is greater than the number of keys left to search through,
	 * we will give this client the remaining tasks (keys) left to do work on.
	 *
	 * String passed back follows format of:
	 *
	 * 	'InitialKey: <@currentkey>\tChunkSize: <@determinedChunkValue>'
	 *
	 * @param clientChunkSize what chunksize (number of keys) the client wants to work on
	 * @return String passed back via socket to Client to know what to work on.
	 */
	public synchronized String getTaskString(Integer clientChunkSize) {
		Long chunkValue = Math.min(tasksLeft(), clientChunkSize);
		String response = KeyManagerConnection.REQUEST_WORK_RESP_1 + currentKey + "\t"
						+ KeyManagerConnection.REQUEST_WORK_RESP_2 + chunkValue + "\t"
						+ KeyManagerConnection.REQUEST_WORK_RESP_3 + keySize() +  "\t"
						+ KeyManagerConnection.REQUEST_WORK_RESP_4 + ciphertext() + "\t";

		currentKey.getAndAdd(chunkValue);
		return response;
	}


	public AtomicLong currentKey() {
		return currentKey;
	}

	public boolean tasksExist() {
		return Math.pow(2, 8*keySize) - currentKey().get() > 0;
	}

	public Long tasksLeft() {
		return Math.round(Math.pow(2, 8*keySize)) - currentKey.get();
	}

	public int keySize() {
		return keySize;
	}

	public String ciphertext() {
		return ciphertext;
	}

	public void closeAndFinish() {
		keyFound = true;
		endTimer = System.currentTimeMillis();
		Long timeTaken = endTimer - startTimer;
		System.out.println("It took " + timeTaken + " ms to find the key");

		// Close off socket
		try {
			sock.close();
		}
		catch (IOException ignored) {}
	}

	public boolean keyFound() {
		return keyFound;
	}
}