import javafx.util.Pair;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class Client {

	private static String localhost;
	private static Integer port;
	private static Integer chunksize;

	// Interruption Handling
	private static boolean criticalSection = false;
	private static boolean shutdownRequested;

	public static void main(String[] args) {

		validateInput(args);

		// If client presses Ctrl-C
		addClientInterruptHook();

		BufferedReader in;
		PrintWriter out;
		Socket sock;

		// Main loop
		while (isKeyManagerRunning(localhost, port) && !shutdownRequested) {
			if (tasksExist(localhost, port)) {
				try {
					// Open new connection
					sock = new Socket(localhost, port);

					// Set up the necessary communication channels
					in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
					out = new PrintWriter(sock.getOutputStream(),true);

					// After this point, we want everything to succeed without interruption, hence, the critical section.
					criticalSection = true;

					// Request work
					out.println("" + KeyManagerConnection.REQUEST_WORK + chunksize);

					// Get work and close connections
					String workInfo = in.readLine();
					System.out.println("From Server: " + workInfo);
					sock.close();
					out.close();
					in.close();

					// Parse server response from work request
					String[] res = workInfo.split("\t");
					String initialKeyString = res[0].substring(KeyManagerConnection.REQUEST_WORK_RESP_1.length(), res[0].length());
					String chunkSizeString = res[1].substring(KeyManagerConnection.REQUEST_WORK_RESP_2.length(), res[1].length());
					String keySizeString = res[2].substring(KeyManagerConnection.REQUEST_WORK_RESP_3.length(), res[2].length());
					String cipherText = res[3].substring(KeyManagerConnection.REQUEST_WORK_RESP_4.length(), res[3].length());

					BigInteger initialKey = BigInteger.valueOf(Long.parseLong(initialKeyString));
					Integer chunkSize = Integer.parseInt(chunkSizeString);
					Integer keySize = Integer.parseInt(keySizeString);

					// Do work
					ClientSearch search = new ClientSearch(initialKey, keySize, chunkSize, cipherText);
					// Get result
					Pair<Boolean, ClientSearch.Result> p = search.attempt();

					// We need to send the results to the key manager
					sock = new Socket(localhost, port);
					// Set up the necessary communication channels
					out = new PrintWriter(sock.getOutputStream(),true);

					// Open connection, send message to server telling it we've found the key.
					if (p.getKey()) {
						System.out.println("I found the key!");
						// Tell server we've found the key, supply information about the key.
						out.println(KeyManagerConnection.KEY_FOUND + p.getValue().key + ", " + p.getValue().keyInHex);
					}
					else {
						out.println(KeyManagerConnection.KEY_NOT_FOUND);
					}

					// Close connection
					out.close();
					sock.close();

					// Work has been completed, we can safely terminate the client here
					criticalSection = false;
				}
				catch (IOException e) {	}
			}
		}
	}

	/**
	 * Validates the command line inputs passed into Client
	 *
	 * Also checks if the KeyManager socket is open. If not,
	 * no point starting client.
	 *
	 * @param 	args size of args should be 3
	 * 			args[0] hostname
	 * 			args[1] port
	 * 			args[2] chunksize
	 */
	private static void validateInput(String[] args) {
		// CLI Validation
		if (args.length != 3) {
			System.err.println("Usage: java Client <IP Address> <Port Number> <Chunksize>");
			System.exit(1);
		}
		localhost = args[0];

		try { port = Integer.parseInt(args[1]);	}
		catch (NumberFormatException e) { e.printStackTrace(); }

		try { chunksize = Integer.parseInt(args[2]);	}
		catch (NumberFormatException e) { e.printStackTrace(); }

		if (!isKeyManagerRunning(localhost, port)) {
			// No point connecting if there's so server running.
			System.err.println("No server running on " + localhost + ":" + port + " to make requests. Ending client connect.");
			System.exit(0);
		}
	}

	/**
	 * Allows the client to leave (requirement 2) but only when work is finished
	 * Essentially when an interrupt is fired (Ctrl-C), this flags that a shutdown
	 * of this client is requested and waits until it's safe to leave (i.e all work
	 * has been completed)
	 */
	private static void addClientInterruptHook() {
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			System.out.println("Shutdown requested. Ensuring work complete before shutting down.");
			shutdownRequested = true; // Stops Client thread from doing more work when finished

			// Stops this thread from ending immediately. End when work in Client thread is done.
			while (criticalSection) {
				try { Thread.sleep(1); }
				catch (InterruptedException ignored) { }
			}

			System.out.println("Work finished. Shutting client down...");
			try { Thread.sleep(200); }
			catch (InterruptedException ignored) { }

			Runtime.getRuntime().halt(0);
		}));
	}

	/**
	 * Checks with KeyManager that there is still work left to be done.
	 * Sends a message to the key manager and the key manager checks its
	 * domain model to see whether there is work left or not.
	 *
	 * Should only be called if isKeyManagerRunning() returns true.
	 *
	 * @param localhost hostname of socket that KeyManager is running
	 * @param port port of socket that KeyManager is running
	 * @return
	 */
	private static boolean tasksExist(String localhost, Integer port) {
		BufferedReader in;
		PrintWriter out;
		Socket sock;

		boolean tasksExist = false;
		try {
			// Request connection to KeyManager
			sock = new Socket(localhost, port);

			// Set up the necessary communication channels
			in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			out = new PrintWriter(sock.getOutputStream(),true);

			// Is there work left?
			out.println(KeyManagerConnection.REQUEST_IS_WORK_LEFT);
			try { tasksExist = Boolean.parseBoolean(in.readLine()); }
			catch (NumberFormatException e) { e.printStackTrace(); }

			// Close connection
			sock.close();
			in.close();
			out.close();
		}
		catch (IOException e) {
		}
		return tasksExist;
	}


	/**
	 * Checks if we can make a connection to the KeyManager connection socket
	 * Run on init to check whether the port supplied to the client in CLI
	 * is actually a socket that is open and accepting connections
	 *
	 * @param hostName hostname of socket that KeyManager is running
	 * @param port port of socket that KeyManagers is running
	 * @return
	 */
	public static boolean isKeyManagerRunning(String hostName, int port) {
		boolean isAlive;

		// Creates a socket address from a hostname and a port number
		SocketAddress socketAddress = new InetSocketAddress(hostName, port);
		Socket socket = new Socket();

		// Timeout required - it's in milliseconds
		int timeout = 1500;
		try {
			socket.connect(socketAddress, timeout);
			socket.close();
			isAlive = true;
		}
		catch (IOException exception) {
			isAlive = false;
		}
		return isAlive;
	}
}