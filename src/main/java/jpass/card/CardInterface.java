package jpass.card;

import jpass.data.DataModel;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.CardException;

import applets.SimpleApplet;

import java.util.Arrays;


public class CardInterface {

	public final byte selectCardManager[] = { (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x07,
			(byte) 0xa0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x18, (byte) 0x43, (byte) 0x4d };

	public final byte appletAID[] = { (byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41,
			(byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74 };

	public final byte selectApplet[] = { (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, (byte) 0x4C,
			(byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C,
			(byte) 0x65, (byte) 0x74 };

	static CardManager cardManager = new CardManager();
	private String error = null;

	public String getError() {
		return error;
	}

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

	// TODO: remove simulated card from final version
    /**
     * Connects to smartcard or Prepares simulator.
     *
     * @param simulator present
     * @return success of session creation
     */
	public boolean InitSession(boolean simulator) {
		if (simulator) {
			// Simulated smartcard
			byte[] installData = new byte[10];
			cardManager.prepareLocalSimulatorApplet(appletAID, installData, SimpleApplet.class);
		} else {
			// Real smartcard
			try {
				if (cardManager.ConnectToCard()) {
					ResponseAPDU output = cardManager.sendAPDU(selectApplet);
				} else {
					this.error = cardManager.getError_state();
					return false;
				}
			} catch (Exception CardException) {
				this.error = cardManager.getError_state();
				// e.printStackTrace();
				return false;
			}
		}
		return true;
	}

    /**
     * Disconnects from smartcard.
     *
     * @param simulator present
     * @return success of session deletion
     */
	public boolean CloseSession(boolean simulator) {
		if (!simulator) {
			try {
				cardManager.DisconnectFromCard();
			} catch (Exception e) {
				this.error = "Close Session : " + e;
				// e.printStackTrace();
				return false;
			}
		}
		return true;
	}

    /**
     * Generate password on smartcard.
     *
     * @param passwordLength length of desired password
     * @return the password
     */
	public String GeneratePassword(int passwordLength) {
		String password = null;

		byte DataLength = 0x00;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x62;	
		apdu[CardManager.OFFSET_P1] = (byte) passwordLength;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		try {
			// ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] response = cardManager.sendAPDUSimulator(apdu);
			password = Arrays.toString(response);
		} catch (Exception e) {
			this.error = "Generate Password : " + e;
		}

		return password;
	}

    /**
     * Set PIN on smartcard.
     *
     * @param pin user input
     * @return success of PIN verification
     */
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
			// ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] response = cardManager.sendAPDUSimulator(apdu);
			byte[] valid = {(byte) 0x90, (byte) 0x00};
			if (Arrays.equals(response, valid)) {
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
     * @param pin user input
     * @return success of PIN verification
     */
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
			// ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] response = cardManager.sendAPDUSimulator(apdu);
			byte[] valid = {(byte) 0x90, (byte) 0x00};
			if (Arrays.equals(response, valid)) {
				state = true;
			} else {
				this.error = "Invalid PIN";
			}
		} catch (Exception e) {
			this.error = "Verify PIN : " + e;
		}

		return state;
	}

	// TODO
	public DataModel LoadData() {
		DataModel ADT = DataModel.getInstance();

		byte DataLength = 0x00;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x00;
		apdu[CardManager.OFFSET_P1] = (byte) 0x00;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		try {
			// ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] response = cardManager.sendAPDUSimulator(apdu);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ADT;
	}

	// TODO
	public boolean SaveData(DataModel ADT) {
		boolean state = false;

		byte DataLength = 0x00;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x00;
		apdu[CardManager.OFFSET_P1] = (byte) 0x00;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		try {
			// ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] response = cardManager.sendAPDUSimulator(apdu);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return state;
	}

	// TODO
	public AppletState GetState() {

		byte DataLength = 0x00;
		byte apdu[] = new byte[CardManager.HEADER_LENGTH + DataLength];
		apdu[CardManager.OFFSET_CLA] = (byte) 0xB0;
		apdu[CardManager.OFFSET_INS] = (byte) 0x00;
		apdu[CardManager.OFFSET_P1] = (byte) 0x00;
		apdu[CardManager.OFFSET_P2] = (byte) 0x00;
		apdu[CardManager.OFFSET_LC] = DataLength;
		try {
			// ResponseAPDU response = cardManager.sendAPDU(apdu);
			byte[] response = cardManager.sendAPDUSimulator(apdu);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return AppletState.NEW;
	}
}
