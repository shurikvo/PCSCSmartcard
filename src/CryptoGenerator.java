import java.io.*;
import java.util.*;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

class CryptoGenerator {
	private static final String ClassName = "CryptoGenerator";

	public String Message = "";

	private ByteMatter byt = new ByteMatter();

	public byte[] genMACSuper(byte[] bKey, byte[] bCipher, int Lcip, byte[] bMAC, int nMode) {
		int i, j, L;
		byte[] bData, bTmp = {0,0,0,0,0,0,0,0};
		
		if(Lcip > bCipher.length) Lcip = bCipher.length;
		
		L = Lcip + 1;
		if((L % 8) != 0)
			L = (L / 8 + 1) * 8;
		bData = new byte[L];
		for(i = 0; i < Lcip; ++i)
			bData[i] = bCipher[i];
		bData[i++] = (byte)0x80;
		for(; i < L; ++i)
			bData[i] = (byte)0x00;
		
		L = bData.length / 8;
		for (i = 0; i < (L - 1); ++i) {
			for (j = 0; j < 8; ++j)
				bTmp[j] = (byte)(bMAC[j] ^ bData[(i * 8) + j]);

			if (nMode == 2)
				bMAC = des(bKey, bTmp, "ECB", null);
			else
				bMAC = des3(bKey, bTmp, "ECB", null);
		}
		for (j = 0; j < 8; j++)
			bTmp[j] = (byte)(bMAC[j] ^ bData[(i * 8) + j]);

		bMAC = des3(bKey, bTmp, "ECB", null);

		return bMAC;
	}

	public byte[] genMACSuper(byte[] bKey, byte[] bCipher, byte[] bMAC, int nMode) {
		return genMACSuper(bKey, bCipher, bCipher.length, bMAC, nMode);
	}

	public byte[] deriveKey(byte[] bKey, byte[] bCipher, String sMode) {
		byte[] bNewKey, bIV = {0,0,0,0,0,0,0,0};
		
		bNewKey = des3(bKey, bCipher, sMode, bIV);
		if(bNewKey == null)
			return null;

		return normalize(bNewKey);
	}

	public byte[] unDes3(byte[] bKey, byte[] bCipher, String sMode, byte[] bIV) {
		byte[] bRes = null, bKey3, bRes3;
		int i;
		
		Message = "";
		if(sMode != "CBC" && sMode != "ECB") {
			Message = ClassName+": Cryption mode is wrong";
			return null;
		}
		if(sMode == "CBC" && bIV == null) {
			Message = ClassName+": There must be IV in CBC mode";
			return null;
		}
		if(sMode == "CBC" && bIV.length != 8) {
			Message = ClassName+": Wrong IV length";
			return null;
		}
		
		if(bKey.length < 24) {
			bKey3 = new byte[24];
			for(i = 0; i < 8; ++i) {
				bKey3[i] = bKey[i];
				bKey3[i+8] = bKey[i+8];
				bKey3[i+16] = bKey[i];
			}
		} else 
			bKey3 = bKey;
		
		try {
			SecretKey key = new SecretKeySpec(bKey3, "DESede");
			Cipher cipher = Cipher.getInstance("DESede/"+sMode+"/NoPadding");
			if(sMode == "CBC") {
				IvParameterSpec iv = new IvParameterSpec(bIV);
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, key);
			}
			bRes = cipher.doFinal(bCipher);
		} catch (NoSuchAlgorithmException | InvalidKeyException |
			NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
			InvalidAlgorithmParameterException e) {
			Message = ClassName+": unDes3: "+e.getMessage();
			return null;
		}
		return bRes;
	}

	public byte[] unDes(byte[] bKey, byte[] bCipher, String sMode, byte[] bIV) {
		byte[] bRes = null;
		
		Message = "";
		if(sMode != "CBC" && sMode != "ECB") {
			Message = ClassName+": Cryption mode is wrong";
			return null;
		}
		if(sMode == "CBC" && bIV == null) {
			Message = ClassName+": There must be IV in CBC mode";
			return null;
		}
		if(sMode == "CBC" && bIV.length != 8) {
			Message = ClassName+": Wrong IV length";
			return null;
		}
		
		try {
			SecretKeyFactory MyKeyFactory = SecretKeyFactory.getInstance("DES");
			DESKeySpec generatedKeySpec = new DESKeySpec(bKey);
			SecretKey generatedSecretKey = MyKeyFactory.generateSecret(generatedKeySpec);
			Cipher generatedCipher = Cipher.getInstance("DES/"+sMode+"/NoPadding");
			if(sMode == "CBC") {
				IvParameterSpec iv = new IvParameterSpec(bIV);
				generatedCipher.init(Cipher.DECRYPT_MODE, generatedSecretKey, iv);
			} else {
				generatedCipher.init(Cipher.DECRYPT_MODE, generatedSecretKey);
			}
			bRes = generatedCipher.doFinal(bCipher);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
			NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
			InvalidAlgorithmParameterException e) {
			Message = ClassName+": unDes: "+e.getMessage();
			return null;
		}
		return bRes;
	}

	public byte[] des3(byte[] bKey, byte[] bCipher, String sMode, byte[] bIV) {
		byte[] bRes = null, bKey3, bRes3;
		int i;
		
		Message = "";
		if(sMode != "CBC" && sMode != "ECB") {
			Message = ClassName+": Cryption mode is wrong";
			return null;
		}
		if(sMode == "CBC" && bIV == null) {
			Message = ClassName+": There must be IV in CBC mode";
			return null;
		}
		if(sMode == "CBC" && bIV.length != 8) {
			Message = ClassName+": Wrong IV length";
			return null;
		}
		
		if(bKey.length < 24) {
			bKey3 = new byte[24];
			for(i = 0; i < 8; ++i) {
				bKey3[i] = bKey[i];
				bKey3[i+8] = bKey[i+8];
				bKey3[i+16] = bKey[i];
			}
		} else 
			bKey3 = bKey;
		
		try {
			SecretKey key = new SecretKeySpec(bKey3, "DESede");
			Cipher cipher = Cipher.getInstance("DESede/"+sMode+"/NoPadding");
			if(sMode == "CBC") {
				IvParameterSpec iv = new IvParameterSpec(bIV);
				cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			} else {
				cipher.init(Cipher.ENCRYPT_MODE, key);
			}
			bRes = cipher.doFinal(bCipher);
		} catch (NoSuchAlgorithmException | InvalidKeyException |
			NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
			InvalidAlgorithmParameterException e) {
			Message = ClassName+": des3: "+e.getMessage();
			return null;
		}
		return bRes;
	}

	public byte[] des(byte[] bKey, byte[] bCipher, String sMode, byte[] bIV) {
		byte[] bRes = null;
		
		Message = "";
		if(sMode != "CBC" && sMode != "ECB") {
			Message = ClassName+": Cryption mode is wrong";
			return null;
		}
		if(sMode == "CBC" && bIV == null) {
			Message = ClassName+": There must be IV in CBC mode";
			return null;
		}
		if(sMode == "CBC" && bIV.length != 8) {
			Message = ClassName+": Wrong IV length";
			return null;
		}
		
		try {
			SecretKeyFactory MyKeyFactory = SecretKeyFactory.getInstance("DES");
			DESKeySpec generatedKeySpec = new DESKeySpec(bKey);
			SecretKey generatedSecretKey = MyKeyFactory.generateSecret(generatedKeySpec);
			Cipher generatedCipher = Cipher.getInstance("DES/"+sMode+"/NoPadding");
			if(sMode == "CBC") {
				IvParameterSpec iv = new IvParameterSpec(bIV);
				generatedCipher.init(Cipher.ENCRYPT_MODE, generatedSecretKey, iv);
			} else {
				generatedCipher.init(Cipher.ENCRYPT_MODE, generatedSecretKey);
			}
			bRes = generatedCipher.doFinal(bCipher);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
			NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
			InvalidAlgorithmParameterException e) {
			Message = ClassName+": des: "+e.getMessage();
			return null;
		}
		return bRes;
	}

	public byte[]  normalize(byte[] key) {
		int i, j, mask, cnt;
		byte[] normKey = new byte[key.length];
		
		for (i = 0; i < key.length; i++) {
			mask = 0x80;
			cnt = 0;
			for (j = 0; j < 8; ++j) {
				if ((byte)(key[i] & mask) != 0)
					cnt++;
				mask >>= 1;
			}
			if ((cnt % 2) == 0){
				if ((key[i] % 2) != 0)
					normKey[i] = (byte)(key[i] & 0xFE);
				else normKey[i] = (byte)(key[i] | 1);
			} else
			 normKey[i] = key[i];
		}
		return normKey;
	}

/*
Every implementation of the Java platform is required to support the following standard Cipher transformations with the keysizes in parentheses:
AES/CBC/NoPadding (128)
AES/CBC/PKCS5Padding (128)
AES/ECB/NoPadding (128)
AES/ECB/PKCS5Padding (128)

DES/CBC/NoPadding (56)
DES/CBC/PKCS5Padding (56)
DES/ECB/NoPadding (56)
DES/ECB/PKCS5Padding (56)

DESede/CBC/NoPadding (168)
DESede/CBC/PKCS5Padding (168)
DESede/ECB/NoPadding (168)
DESede/ECB/PKCS5Padding (168)

RSA/ECB/PKCS1Padding (1024, 2048)
RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
*/
}