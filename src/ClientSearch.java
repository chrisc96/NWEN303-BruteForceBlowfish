import javafx.util.Pair;

import java.math.BigInteger;

public class ClientSearch {

	private BigInteger bi;
	private int keySize;
	private int keyRange;
	private byte[] key;
	private byte[] cipherText;

	public ClientSearch(BigInteger bi, int keySize, int keyRange, String cipherText) {
		this.bi = bi;
		this.keySize = keySize;
		this.keyRange = keyRange;
		this.cipherText = Blowfish.fromBase64(cipherText);
		key = Blowfish.asByteArray(bi, keySize);
	}

	public Pair<Boolean, Result> attempt() {

		// Pair to return to client if plaintext not found
		Pair<Boolean, Result> notFound = new Pair<>(false, null);

		String plaintext;
		// Search from the key that will give us our desired ciphertext
		for (int i = 0; i < keyRange; i++) {
			String keyStr = bi.toString();
			for (int j = 0; j < keyStr.length(); j++) {
				System.out.print("\b");
			}

			// decrypt and compare to known plaintext
			Blowfish.setKey(key);
			plaintext = Blowfish.decryptToString(cipherText);

			if (plaintext.equals("May good flourish; Kia hua ko te pai")) {
				return new Pair<>(true, new Result(bi, Blowfish.toHex(key)));
			}

			// try the next key
			bi = bi.add(BigInteger.ONE);
			key = Blowfish.asByteArray(bi, keySize);
		}
		// If no key found at this point, return the pair that represents this.
		return notFound;
	}

	class Result {

		BigInteger key;
		String keyInHex;

		public Result(BigInteger key, String keyInHex) {
			this.key = key;
			this.keyInHex = keyInHex;
		}
	}

}
