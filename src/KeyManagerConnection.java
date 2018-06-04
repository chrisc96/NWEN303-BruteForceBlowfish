import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;

/**
 * KeyManagerConnection is a thread based implementation that handles the interactions
 * between the Client/Server architecture that exists between the Client and KeyManager. This
 * is all done over sockets.
 */
public class KeyManagerConnection extends Thread {

	// Standardising REQUESTS/RESPONSES (without Regex patterns, cba)
	// These are what clients send to this Connection or what the server sends back.
	static String REQUEST_IS_WORK_LEFT = "Work_Left?";

	static String REQUEST_WORK = "Requesting Work: ";
	static String REQUEST_WORK_RESP_1 = "InitialKey: ";
	static String REQUEST_WORK_RESP_2 = "ChunkSize: ";
	static String REQUEST_WORK_RESP_3 = "KeySize: ";
	static String REQUEST_WORK_RESP_4 = "CipherText: ";

	static String KEY_FOUND = "Key Found: ";
	static String KEY_NOT_FOUND = "Key Not Found: ";


	private Socket client; // Client
	private KeyManager manager; // Server domain model

	public KeyManagerConnection(Socket client, KeyManager keyManager) {
		this.client = client;
		this.manager = keyManager;
	}

	public void run() {
		BufferedReader networkBin = null;
		OutputStreamWriter networkPout = null;

		try {
			networkBin = new BufferedReader(new InputStreamReader(client.getInputStream()));
			networkPout = new OutputStreamWriter(client.getOutputStream());

			String response = null;
			while (true) {
				String line = networkBin.readLine();

				// Line == null when a client writes to a socket stream without anything in it (i.e socket.connect())
				// This happens in isKeyManagerRunning() or tasksExist() in Client.java. No messages passed so ignore.
				if (line == null) {
					break;
				}
				System.out.println("\nA client sends: " + line);

				// Client could have sent:
				if (line.contains(REQUEST_WORK)) {
					Integer clientChunkSize;
					try {
						String s = line.substring(line.lastIndexOf(REQUEST_WORK) + REQUEST_WORK.length(), line.length());
						clientChunkSize = Integer.parseInt(s);
						response = manager.getTaskString(clientChunkSize);
					}
					catch (NumberFormatException e) {
						System.err.println("Request work message should follow format of 'Requesting Work: ChunkSize'");
						System.exit(1);
					}
				}


				// OR Client could have sent:
				if (line.equalsIgnoreCase(REQUEST_IS_WORK_LEFT)) {
					response = "" + (manager.tasksExist() && !manager.keyFound());
				}

				// OR Client could have sent:
				if (line.equalsIgnoreCase(KEY_NOT_FOUND)) {
					// A client didn't find the key, no point printing anything to KeyManager console...
				}

				// OR Client could have sent:
				else if (line.contains(KEY_FOUND)) {
					System.out.println("\nWooo we found the key!");
					manager.closeAndFinish();
					break;
				}

				// Send the servers response back to the client
				networkPout.write(response + "\r\n");
				System.out.println("Server Responds: " + response);

				// Force the send to prevent buffering
				networkPout.flush();
			}
		}
		catch (IOException ignored) { }
		finally {
			try {
				if (networkBin != null)	networkBin.close();
				if (networkPout != null)networkPout.close();
				if (client != null)		client.close();
			}
			catch (IOException ignored) {}
		}
	}
}
