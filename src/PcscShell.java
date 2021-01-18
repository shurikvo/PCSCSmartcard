import java.util.List;
import javax.smartcardio.*;


public class PcscShell {
	public int SW;
	public ResponseAPDU answer;
	public List<CardTerminal> terminals;
	public CardTerminal terminal;
	public Card card;
	public CardChannel channel;
	
	private ByteMatter byt;
	private VLogger log;
	
	public PcscShell(String sProject) {
		int i;
		
		byt = new ByteMatter();
		try {
			if(sProject.length() > 0) {
				log = new VLogger();
				log.init(sProject);
			}
			// Display the list of terminals
			TerminalFactory factory = TerminalFactory.getDefault();
			terminals = factory.terminals().list();
			System.out.println("Card readers: ");
			for(i = 0; i < terminals.size(); ++i) {
				log.writeMes(LogMesType.INFO, i + ": " + terminals.get(i).getName());
			}
		} catch(Exception e) {
			log.writeMes(LogMesType.ERROR, "PcscShell: " + e.toString());
		}
	}
	
	public int connectCard(int N) {
		try {
			terminal = terminals.get(N);
			card = terminal.connect("*");
			System.out.println("card: " + card);
			channel = card.getBasicChannel();
		} catch(Exception e) {
			log.writeMes(LogMesType.ERROR, "connectCard: " + e.toString());
			return -1;
		}
		return 0;
	}
	
	public int disconnectCard() {
		try {
			card.disconnect(false);
		} catch(Exception e) {
			log.writeMes(LogMesType.ERROR, "disconnect: " + e.toString());
			return -1;
		}
		return 0;
	}
	
	public String sendAPDU(String sAPDU) {
		byte[] bAPDU, bAnswer;
		String sOut = "";
		
		try {
			bAPDU = byt.toByteArray(sAPDU);
			log.writeMes(LogMesType.INFO, "> " + byt.toHexString(bAPDU));
			answer = channel.transmit(new CommandAPDU(bAPDU));
			SW = answer.getSW();
			bAnswer = answer.getData();
			sOut = byt.toHexString(bAnswer);
			log.writeMes(LogMesType.INFO, "< " + sOut + " " + Integer.toHexString(SW));

		} catch(Exception e) {
			log.writeMes(LogMesType.ERROR, "sendAPDU: " + e.toString());
			return "";
		}
		
		return sOut;
	}
}