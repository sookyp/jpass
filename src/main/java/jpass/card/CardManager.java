package jpass.card;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.List;
import javacard.framework.AID;
import javax.smartcardio.*;

public class CardManager {

	protected CardTerminal m_terminal = null;
	protected CardChannel m_channel = null;
	protected Card m_card = null;

	private String error_state = null;

	// Simulator related attributes
	private static CAD m_cad = null;
	private static JavaxSmartCardInterface m_simulator = null;

	public static final byte OFFSET_CLA = 0x00;
	public static final byte OFFSET_INS = 0x01;
	public static final byte OFFSET_P1 = 0x02;
	public static final byte OFFSET_P2 = 0x03;
	public static final byte OFFSET_LC = 0x04;
	public static final byte OFFSET_DATA = 0x05;
	public static final byte HEADER_LENGTH = 0x05;
	public final static short DATA_RECORD_LENGTH = (short) 0x80; // 128B per
																	// record
	public final static short NUMBER_OF_RECORDS = (short) 0x0a; // 10 records

	public String getError_state() {
		return error_state;
	}

	private void setError_state(String error_state) {
		this.error_state = error_state;
	}

	public boolean ConnectToCard() throws Exception {
		@SuppressWarnings("rawtypes")
		List terminalList = GetReaderList();
		boolean cardFound = false;

		if (terminalList.isEmpty()) {
			setError_state("No terminals found");
			return cardFound;
		}
		// List numbers of Card readers
		for (int i = 0; i < terminalList.size(); i++) {
			m_terminal = (CardTerminal) terminalList.get(i);
			if (m_terminal.isCardPresent()) {
				m_card = m_terminal.connect("*");
				m_channel = m_card.getBasicChannel();

				// reset the card
				ATR atr = m_card.getATR();

				cardFound = true;
			}
		}
		if (!cardFound) {
			setError_state("No card found");
		}
		return cardFound;
	}

	public void DisconnectFromCard() throws Exception {
		if (m_card != null) {
			m_card.disconnect(false);
			m_card = null;
		}
	}

	public List GetReaderList() {
		try {
			TerminalFactory factory = TerminalFactory.getDefault();
			List readersList = factory.terminals().list();
			return readersList;
		} catch (Exception CardException) {
			setError_state("No card readers are available");
			return null;
		}
	}

	// TODO: remove all System.out.println from finished version
	public ResponseAPDU sendAPDU(byte apdu[]) throws Exception {
		CommandAPDU commandAPDU = new CommandAPDU(apdu);

		System.out.println(">>>>");
		System.out.println(commandAPDU);

		System.out.println(bytesToHex(commandAPDU.getBytes()));

		ResponseAPDU responseAPDU = m_channel.transmit(commandAPDU);

		System.out.println(responseAPDU);
		System.out.println(bytesToHex(responseAPDU.getBytes()));

		if (responseAPDU.getSW1() == (byte) 0x61) {
			CommandAPDU apduToSend = new CommandAPDU((byte) 0x00, (byte) 0xC0, (byte) 0x00, (byte) 0x00,
					(int) responseAPDU.getSW1());

			responseAPDU = m_channel.transmit(apduToSend);
			System.out.println(bytesToHex(responseAPDU.getBytes()));
		}

		System.out.println("<<<<");

		return (responseAPDU);
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

	public boolean prepareLocalSimulatorApplet(byte[] appletAIDArray, byte[] installData, Class appletClass) {
		System.setProperty("com.licel.jcardsim.terminal.type", "2");
		m_cad = new CAD(System.getProperties());
		m_simulator = (JavaxSmartCardInterface) m_cad.getCardInterface();
		AID appletAID = new AID(appletAIDArray, (short) 0, (byte) appletAIDArray.length);

		AID appletAIDRes = m_simulator.installApplet(appletAID, appletClass, installData, (short) 0,
				(byte) installData.length);
		return m_simulator.selectApplet(appletAID);
	}

	// TODO: remove all System.out.println from finished version
	public byte[] sendAPDUSimulator(byte apdu[]) throws Exception {
		System.out.println(">>>>");
		System.out.println(bytesToHex(apdu));

		byte[] responseBytes = m_simulator.transmitCommand(apdu);

		System.out.println(bytesToHex(responseBytes));
		System.out.println("<<<<");

		return responseBytes;
	}

}
