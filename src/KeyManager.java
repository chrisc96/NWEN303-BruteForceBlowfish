import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicLong;

public class KeyManager {


	private AtomicLong currentKey = null;
	private String ciphertext = null;
	private int keySize = 4; // 4 bytes at minimum as Blowfish supports 32-448 bit key sizes (4 bytes = 32 bit)

	ServerSocket sock;

	// How long to find the decryption key
	long startTimer;
	long endTimer;
	private boolean firstConnect = true; // Used to start timer on first socket connection

	private boolean keyFound = false;

	public KeyManager(String[] args) {
		CLIValidation(args);
		acceptConnections();
	}

	/**
	 * Validates the command line inputs passed into Client
	 *
	 *
	 * @param 	args size of args should be 3
	 * 			args[0] initialKey to start searching from
	 * 			args[1] keySize
	 * 			args[2] ciphertext of encrypted text
	 */
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

	/**
	 * We setup a socket connection for our clients to connect to.
	 * The communication is handled in a separate thread for each client so socket
	 * requests are not coupled with server workload of message passing
	 */
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

		// We need to increment our current key by the work that the client is going to be doing
		currentKey.getAndAdd(chunkValue);
		return response;
	}

	/**
	 * Given the key size in bytes, we know 8 * keySize is the number of bits of the keysize
	 * which represents the key space. 2^keyspace is the potential number of keys that the
	 * cipher can adopt as its key. Thus, given a current key value, and a maximum keyspace,
	 * we can determine that if 2^keyspace - currentKey that we're looking at is > 0 then
	 * we still have tasks left to do (where tasks are just keys that haven't been explored)
	 *
	 * @return boolean if there are keys still left to search
	 */
	public boolean tasksExist() {
		return Math.pow(2, 8*keySize) - currentKey().get() > 0;
	}

	/**
	 * Does the same as @tasksExist() but instead of returning a boolean
	 * returns the actual number of keys left to search.
	 * @return number of keys left to use to decrypt
	 */
	public Long tasksLeft() {
		return Math.round(Math.pow(2, 8*keySize)) - currentKey.get();
	}

	/**
	 * When the key has been found, a message is passed to the KeyManagerConnection
	 * from the Client, the KeyManagerConnection then tells us to clean up and end as
	 * we have found the key.
	 *
	 * This is the process of doing that.
	 */
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


	/**
	 * We use an AtomicLong for thread safety purposes so that a single client gets given assigned work
	 * and then currentKey gets incremented by the individual amount of work that that client is expected to do.
	 *
	 * @return
	 */
	public AtomicLong currentKey() {
		return currentKey;
	}

	// Getters are Setters

	public int keySize() {
		return keySize;
	}

	public String ciphertext() {
		return ciphertext;
	}

	public boolean keyFound() {
		return keyFound;
	}

	// Main
	public static void main (String[] args) {
		new KeyManager(args);
	}
}