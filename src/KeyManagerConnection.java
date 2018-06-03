import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;

public class KeyManagerConnection extends Thread {

	// Standardising REQUESTS/RESPONSES (without Regex patterns, cba)
	// These are what clients send to this Connection or what the server can send back.
	static String REQUEST_IS_WORK_LEFT = "Work_Left?";

	static String REQUEST_WORK = "Requesting Work: ";
	static String REQUEST_WORK_RESP_1 = "InitialKey: ";
	static String REQUEST_WORK_RESP_2 = "ChunkSize: ";
	static String REQUEST_WORK_RESP_3 = "KeySize: ";
	static String REQUEST_WORK_RESP_4 = "CipherText: ";

	static String KEY_FOUND = "Key Found: ";

	private Socket client;
	private KeyManager manager;

	public KeyManagerConnection(Socket client, KeyManager keyManager) {
		this.client = client;
		this.manager = keyManager;
	}

	public void run() {
		BufferedReader networkBin = null;
		OutputStreamWriter networkPout = null;

		try {
			/**
			 * get the input and output streams associated with the socket.
			 */
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

				if (line.equalsIgnoreCase(REQUEST_IS_WORK_LEFT)) {
					response = "" + (manager.tasksExist() && !manager.keyFound());
				}

				// We found the key!
				if (line.contains(KEY_FOUND)) {
					System.out.println("\nWooo we found the key!");
					manager.closeAndFinish();
					break;
				}

				networkPout.write(response + "\r\n");
				System.out.println("Server Responds: " + response);
				// force the send to prevent buffering
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
