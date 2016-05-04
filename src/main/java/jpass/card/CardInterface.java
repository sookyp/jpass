package jpass.card;

import jpass.data.DataModel;
import jpass.data.DocumentHelper;
import jpass.data.DocumentProcessException;
import jpass.ui.JPassFrame;
import jpass.ui.helper.FileHelper;
import jpass.xml.bind.Entries;
import jpass.xml.bind.Entry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.io.FileNotFoundException;
import jpass.xml.converter.JAXBConverter;

public class CardInterface {

	public final byte selectApplet[] = { (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74 };

	static CardManager cardManager = new CardManager();
	private String error = null;

	public String getError() {
		return error;
	}

	private static final JAXBConverter<Entries> CONVERTER = new JAXBConverter<Entries>(Entries.class, "resources/schemas/entries.xsd");

	static private enum AppletState {
		NEW(0), BASIC(15), AUTHENTICATED(255);
		// NEW = 0x00, BASIC = 0x0F, AUTHENTICATED = 0xFF
		private int value;

		private AppletState(int value) {
			this.value = value;
		}

		public int getValue() {
			return value;
		}
	}

	/**
	 * Connects to smartcard.
	 *
	 * @return success of session creation
	 */
	@SuppressWarnings("restriction")
	public boolean InitSession() {
		try {
			if (cardManager.ConnectToCard()) {
				ResponseAPDU output = cardManager.sendAPDU(selectApplet);
			} else {
				this.error = cardManager.getError_state();
				return false;
			}
		} catch (Exception e) {
			this.error = cardManager.getError_state();
			// e.printStackTrace();
			return false;
		}
		return true;
	}

	/**
	 * Disconnects from smartcard.
	 *
	 * @return success of session deletion
	 */
	public boolean CloseSession() {
		try {
			cardManager.DisconnectFromCard();
		} catch (Exception e) {
			this.error = "Close Session : " + e;
			// e.printStackTrace();
			return false;
		}
		return true;
	}

	// TODO: test responseAPDU class with real card

	/**
	 * Generate password on smartcard.
	 *
	 * @param passwordLength
	 *            length of desired password
	 * @return the password
	 */
	@SuppressWarnings("restriction")
	public String GeneratePassword(int passwordLength) {
		String password = null;

		byte DataLength = 0x00;
		ResponseAPDU response = null;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x62;
		apdu[CardManager.OFFSET_P1] = (byte) passwordLength;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		try {
			response = cardManager.sendAPDU(apdu);
		} catch (Exception e) {
			this.error = "Generate Password : " + e;
		}
		
		SecureRandom sr;
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
			sr.setSeed(response.getData());
			for(int i = 0; i < response.getData().length; i++) {
				password += sr.nextInt();
			}
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		// password = Arrays.toString(response.getBytes());
		
		return password;
	}

	/**
	 * Set PIN on smartcard.
	 *
	 * @param pin
	 *            user input
	 * @return success of PIN verification
	 */
	@SuppressWarnings("restriction")
	public boolean SetPIN(char[] pin) {
		boolean state = false;

		byte DataLength = (byte) pin.length;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x56;
		apdu[CardManager.OFFSET_P1] = (byte) 0x00;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		for (byte i = 0; i < DataLength; i++) {
			apdu[CardManager.OFFSET_DATA + i] = (byte) (pin[i] - '0');
		}
		try {
			ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] valid = { (byte) 0x90, (byte) 0x00 };
			if (Arrays.equals(response.getBytes(), valid)) {
				state = true;
				this.error = "PIN successfully set.";
			} else {
				this.error = "Issue with PIN initialization";
			}
		} catch (Exception e) {
			this.error = "Set PIN : " + e;
		}

		return state;
	}

	/**
	 * Verify PIN on smartcard.
	 *
	 * @param pin
	 *            user input
	 * @return success of PIN verification
	 */
	@SuppressWarnings("restriction")
	public boolean VerifyPIN(char[] pin) {
		boolean state = false;

		byte DataLength = (byte) pin.length;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x55;
		apdu[CardManager.OFFSET_P1] = (byte) 0x00;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		for (byte i = 0; i < DataLength; i++) {
			apdu[CardManager.OFFSET_DATA + i] = (byte) (pin[i] - '0');
		}
		try {
			ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] valid = { (byte) 0x90, (byte) 0x00 };
			if (Arrays.equals(response.getBytes(), valid)) {
				state = true;
			} else {
				this.error = "Invalid PIN";
			}
		} catch (Exception e) {
			this.error = "Verify PIN : " + e;
		}

		return state;
	}

	// TODO: testing
	/**
	 * Load passwords from smartcard and read entries from file.
	 *
	 * @return list of entries containing all data
	 */
	@SuppressWarnings("restriction")
	public boolean LoadData() {
		boolean state = false;

		DataModel ADT = DataModel.getInstance();
		Entries entries = ADT.getEntries();
		List<Entry> entry_list = entries.getEntry();

		FileHelper.openFile(JPassFrame.getInstance());

		try {
			JPassFrame.getInstance().getModel().setEntries(DocumentHelper.newInstance(JPassFrame.getInstance().filename, JPassFrame.getInstance().password).readDocument());
			JPassFrame.getInstance().getModel().setFileName(JPassFrame.getInstance().filename);
			JPassFrame.getInstance().getModel().setPassword(JPassFrame.getInstance().password);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (DocumentProcessException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		byte DataLength = 0x00;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x61;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		byte index = 0;

		while (true) {

			apdu[CardManager.OFFSET_P1] = index;

			try {
				ResponseAPDU response = cardManager.sendAPDU(apdu);

				byte[] valid = { (byte) 0x90, (byte) 0x00 };
				byte[] full = { (byte) 0x69, (byte) 0x06 };
				if (Arrays.equals(response.getBytes(), valid)) {
					state = true;
				} else if (Arrays.equals(response.getBytes(), full)) {
					state = true;
					break;
				} else {
					this.error = "Error occured while saving the passwords";
				}

				String encryptionKey = "16023FBEB58DF4EB36229286419F4589";
				String IV = "DE46F8904224A0E86E8F8F08F03BCC1A";

				String decrytpted = null;
				byte[] message = response.getData();
				String raw_data = bytesToHex(response.getData());
				
				try {
					Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
				    SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
				    cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
				    decrytpted = new String(cipher.doFinal(message),"UTF-8");
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchProviderException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (NoSuchPaddingException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (UnsupportedEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IllegalBlockSizeException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (BadPaddingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidKeyException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (InvalidAlgorithmParameterException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				// TODO: parse the password
				JPassFrame.getInstance().getModel().getEntries().getEntry().get(index).setPassword(decrytpted);
				index++;
			} catch (Exception e) {

				e.printStackTrace();
				this.error = "Load Data : " + e;
			}

		}

		return true;
	}

	// TODO: testing
	/**
	 * Save passwords to smartcard and write entries to file.
	 *
	 * @return success of operation
	 * @throws IOException
	 */
	@SuppressWarnings("restriction")
	public boolean SaveData() {
		boolean state = false;

		DataModel ADT = DataModel.getInstance();
		List<Entry> entry_list = ADT.getEntries().getEntry();
		byte entry_count = (byte) entry_list.size();
		// conversion
		String data = "";

		String encryptionKey = "16023FBEB58DF4EB36229286419F4589";
		String IV = "DE46F8904224A0E86E8F8F08F03BCC1A";

		for (byte i = 0; i < entry_count; i++) {
			data = "";
			// data += (entry_list.get(i).getTitle());
			// data += "\r\n";
			data += (entry_list.get(i).getPassword());
			data += "\r\n\r\n";

			byte message[] = data.getBytes();
			byte[] encrypted = null;

			try {
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
				SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
			    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
			    encrypted = cipher.doFinal(data.getBytes("UTF-8"));
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchProviderException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (NoSuchPaddingException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (UnsupportedEncodingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (BadPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InvalidAlgorithmParameterException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    	
			
			byte DataLength = (byte) (encrypted.length);

			byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
			apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
			apdu[CardManager.OFFSET_INS] = (byte) 0x58;
			apdu[CardManager.OFFSET_P1] = (byte) i;
			apdu[CardManager.OFFSET_P2] = (byte) (entry_count - i - 1);
			apdu[CardManager.OFFSET_LC] = DataLength;

			for (byte j = 0; j < (byte) DataLength; j++) {
				apdu[CardManager.OFFSET_DATA + j] = encrypted[j];
			}

			try {
				ResponseAPDU response = cardManager.sendAPDU(apdu);
				byte[] valid = { (byte) 0x90, (byte) 0x00 };
				if (Arrays.equals(response.getBytes(), valid)) {
					state = true;
				} else {
					this.error = "Error occured while saving the passwords";
				}

			} catch (Exception e) {
				this.error = "Save Data : " + e;
			}

			entry_list.get(i).setPassword(null);

		}
		FileHelper.saveFile(JPassFrame.getInstance(), true);

		return state;
	}

	public String byteToHex(byte data) {
		StringBuilder buf = new StringBuilder();
		buf.append(toHexChar((data >>> 4) & 0x0F));
		buf.append(toHexChar(data & 0x0F));
		return buf.toString();
	}

	public char toHexChar(int i) {
		if ((0 <= i) && (i <= 9)) {
			return (char) ('0' + i);
		} else {
			return (char) ('a' + (i - 10));
		}
	}

	public String bytesToHex(byte[] data) {
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < data.length; i++) {
			buf.append(byteToHex(data[i]));
			buf.append(" ");
		}
		return (buf.toString());
	}

	public static int hex2decimal(String s) {
		String digits = "0123456789ABCDEF";
		s = s.toUpperCase();
		int val = 0;
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			int d = digits.indexOf(c);
			val = 16 * val + d;
		}
		return val;
	}

}
