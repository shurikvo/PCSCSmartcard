import java.io.*;
import java.util.*;

class KeyChecker {
	private static final String ClassName = "KeyChecker";
	
	public byte CurDiv = (byte)0xFF, CurKey = (byte)0xFF;
	public byte[] HChallenge = new byte[8], CAnswer = new byte[0x28], MAC = new byte[8],
		DKeyENC = new byte[16], DKeyMAC = new byte[16], DKeyDEK = new byte[16], 
		SKeyENC = new byte[16], SKeyMAC = new byte[16], SKeyDEK = new byte[16];
	public String SCP = "02"; 
	
	private String Project;
	private byte[] bDiv = {0, 1, 2};
	private ArrayList<byte[]> MKey = new ArrayList<byte[]>(); 
	
	private VLogger log = new VLogger();
	private ByteMatter byt = new ByteMatter();
	private CryptoGenerator cry = new CryptoGenerator();
	
	public String MakePutKey(int nOld, int nNew, String sNewKey) {
		String sCmd = "";
		
		return sCmd;
	}
	
	public String MakeExtAuth(int nLevel) {
		byte[] bB, bKDD = new byte[16], bIV = new byte[8], 
			bCmd = {(byte)0x84,(byte)0x82,(byte)nLevel,0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
			bCrypto = {0,0,0,0,0,0,0,0};
		int i, RC;
		String sCmd = "";

		if(CAnswer[11]!= 2) {
			log.writeMes(LogMesType.ERROR, ClassName+": Wrong SCP");
			return "";
		}

		for(i = 0; i < 8; ++i) {
			bKDD[i] = CAnswer[12+i]; bKDD[8+i] = HChallenge[i];
			MAC[i] = 0;
		}
		log.writeMes(LogMesType.INFO, "Host: "+byt.toHexString(bKDD));
		bCrypto = cry.genMACSuper(SKeyENC, bKDD, bCrypto, 1);
		log.writeMes(LogMesType.INFO, " Cry: "+byt.toHexString(bCrypto));

		for(i = 0; i < 8; ++i) bCmd[5+i] = bCrypto[i];
		log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bCmd));
		MAC = cry.genMACSuper(SKeyMAC, bCmd, 13, MAC, 2);
		for(i = 0; i < 8; ++i) bCmd[13+i] = MAC[i];

		return byt.toHexString(bCmd);
	}
	
	public int checkKey() {
		int i, j, RC;

		DKeyENC = new byte[16]; DKeyMAC = new byte[16]; DKeyDEK = new byte[16]; 
		SKeyENC = new byte[16]; SKeyMAC = new byte[16]; SKeyDEK = new byte[16];
		CurDiv = (byte)0xFF; CurKey = (byte)0xFF;
		
		for(byte[] b: this.MKey)
			log.writeMes(LogMesType.INFO, "\t"+byt.toHexString(b));
		log.writeMes(LogMesType.INFO, "\t"+byt.toHexString(this.HChallenge));
		log.writeMes(LogMesType.INFO, "\t"+byt.toHexString(this.CAnswer));

		for(i = 0; i < this.MKey.size(); ++i) {
			for(j = 0; j < bDiv.length; ++j) {
				RC = checkCrypto(bDiv[j], this.MKey.get(i));
				if(RC >= 0) {
					CurDiv = (byte)j;
					CurKey = (byte)i;
					return 0;
				}
			}
		}
		return -1;
	}
	
	private int checkCrypto(byte bDiv, byte[] bKey) {
		byte[] bB, bKDD = new byte[16], bIV = new byte[8], bCrypto = {0,0,0,0,0,0,0,0};
		int i, RC;
		
		log.writeMes(LogMesType.INFO, ClassName+": Div: "+bDiv+" Key: "+byt.toHexString(bKey));

		{ // Derivation
			// Flat: --------------------------------------------------------------------------
			if(bDiv == 0) {
				DKeyENC = bKey;
				DKeyMAC = bKey;
				DKeyDEK = bKey;
			} else {
				// GP: ----------------------------------------------------------------------------
				if(bDiv == 1) {
					bKDD[0] = CAnswer[0]; bKDD[ 8] = CAnswer[0];
					bKDD[1] = CAnswer[1]; bKDD[ 9] = CAnswer[1];
					bKDD[2] = CAnswer[4]; bKDD[10] = CAnswer[4];
					bKDD[3] = CAnswer[5]; bKDD[11] = CAnswer[5];
					bKDD[4] = CAnswer[6]; bKDD[12] = CAnswer[6];
					bKDD[5] = CAnswer[7]; bKDD[13] = CAnswer[7];
				}
				// EMV CPS: -----------------------------------------------------------------------
				else if(bDiv == 2) {
					bKDD[0] = CAnswer[4]; bKDD[ 8] = CAnswer[4];
					bKDD[1] = CAnswer[5]; bKDD[ 9] = CAnswer[5];
					bKDD[2] = CAnswer[6]; bKDD[10] = CAnswer[6];
					bKDD[3] = CAnswer[7]; bKDD[11] = CAnswer[7];
					bKDD[4] = CAnswer[8]; bKDD[12] = CAnswer[8];
					bKDD[5] = CAnswer[9]; bKDD[13] = CAnswer[9];
				} else {
					log.writeMes(LogMesType.ERROR, ClassName+": Diversification is wrong");
					return -1;
				}
					bKDD[6] = (byte)0xF0; bKDD[14] = (byte)0x0F;
					// Derived ENC: -------------------------------------------------------------------
					bKDD[7] = (byte)0x01; bKDD[15] = (byte)0x01;
					//log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bKDD));
					DKeyENC = cry.deriveKey(bKey, bKDD, "ECB");
					if(DKeyENC == null) {
						log.writeMes(LogMesType.ERROR, ClassName+": "+cry.Message);
						return -1;
					}
					log.writeMes(LogMesType.INFO, "DENC: "+byt.toHexString(DKeyENC));
					// Derived ENC: -------------------------------------------------------------------
					bKDD[7] = (byte)0x02; bKDD[15] = (byte)0x02;
					//log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bKDD));
					DKeyMAC = cry.deriveKey(bKey, bKDD, "ECB");
					if(DKeyMAC == null) {
						log.writeMes(LogMesType.ERROR, ClassName+": "+cry.Message);
						return -1;
					}
					log.writeMes(LogMesType.INFO, "DMAC: "+byt.toHexString(DKeyMAC));
					// Derived ENC: -------------------------------------------------------------------
					bKDD[7] = (byte)0x03; bKDD[15] = (byte)0x03;
					//log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bKDD));
					DKeyDEK = cry.deriveKey(bKey, bKDD, "ECB");
					if(DKeyDEK == null) {
						log.writeMes(LogMesType.ERROR, ClassName+": "+cry.Message);
						return -1;
					}
					log.writeMes(LogMesType.INFO, "DDEK: "+byt.toHexString(DKeyDEK));
			}
		}

		{ // Diversification
			if(CAnswer[11]!= 2) {
				log.writeMes(LogMesType.ERROR, ClassName+": Wrong SCP");
				return -1;
			}
			
			bKDD[0] = (byte)0x01;  bKDD[1] = (byte)0x82;  bKDD[2] = CAnswer[12]; bKDD[3] = CAnswer[13];
			bKDD[4] = (byte)0x00;  bKDD[5] = (byte)0x00;  bKDD[6] = (byte)0x00;  bKDD[7] = (byte)0x00;
			bKDD[8] = (byte)0x00;  bKDD[9] = (byte)0x00;  bKDD[10] = (byte)0x00; bKDD[11] = (byte)0x00;
			bKDD[12] = (byte)0x00; bKDD[13] = (byte)0x00; bKDD[14] = (byte)0x00; bKDD[15] = (byte)0x00;
			// Session ENC: -------------------------------------------------------------------
			//log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bKDD));
			SKeyENC = cry.deriveKey(DKeyENC, bKDD, "CBC");
			if(SKeyENC == null) {
				log.writeMes(LogMesType.ERROR, ClassName+": "+cry.Message);
				return -1;
			}
			log.writeMes(LogMesType.INFO, "SENC: "+byt.toHexString(SKeyENC));
			// Session MAC: -------------------------------------------------------------------
			bKDD[1] = (byte)0x01;
			//log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bKDD));
			SKeyMAC = cry.deriveKey(DKeyMAC, bKDD, "CBC");
			if(SKeyMAC == null) {
				log.writeMes(LogMesType.ERROR, ClassName+": "+cry.Message);
				return -1;
			}
			log.writeMes(LogMesType.INFO, "SMAC: "+byt.toHexString(SKeyMAC));
			// Session DEK: -------------------------------------------------------------------
			bKDD[1] = (byte)0x81;
			//log.writeMes(LogMesType.INFO, " KDD: "+byt.toHexString(bKDD));
			SKeyDEK = cry.deriveKey(DKeyDEK, bKDD, "CBC");
			if(SKeyDEK == null) {
				log.writeMes(LogMesType.ERROR, ClassName+": "+cry.Message);
				return -1;
			}
			log.writeMes(LogMesType.INFO, "SDEK: "+byt.toHexString(SKeyDEK));
			//---------------------------------------------------------------------------------
		}
		
		{ // Card Crypto
			for(i = 0; i < 8; ++i) {
				bKDD[i] = HChallenge[i]; bKDD[8+i] = CAnswer[12+i];
			}

			byte[] bCardCrypto = new byte[8];
			for(i = 0; i < 8; ++i)
				bCardCrypto[i] = CAnswer[20+i];

			bCrypto = cry.genMACSuper(SKeyENC, bKDD, bCrypto, 1);

			log.writeMes(LogMesType.INFO, byt.toHexString(bCrypto)+" vs "+byt.toHexString(bCardCrypto));
			for(i = 0; i < 8; ++i)
				if(bCrypto[i] != bCardCrypto[i])
					return -1000;
		}
		return 0;
	}

	public int checkKey(String sHChallenge, String sCAnswer) {
		this.HChallenge = byt.toByteArray(sHChallenge);
		this.CAnswer = byt.toByteArray(sCAnswer);
		return checkKey();
	}
	
	public String getDiv() {
		switch(CurDiv) {
		case 0: return "Flat";
		case 1: return "Open Platform";
		case 2: return "EMV CPS";
		}
		return "None";
	}

	public void setHChallenge(String sB) {
		this.HChallenge = byt.toByteArray(sB);
	}

	public void setCAnswer(String sB) {
		this.CAnswer = byt.toByteArray(sB);
	}
	
	public int addMKey(String sMKey) {
		this.MKey.add(byt.toByteArray(sMKey));
		return MKey.size();
	}

	KeyChecker(String sProject) {
		this.Project = sProject;
		log.init(Project);
	}
}