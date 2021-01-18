import javax.xml.bind.DatatypeConverter;

class ByteMatter {
	public static String toHexString(byte[] array) {
		return DatatypeConverter.printHexBinary(array);
	}

	public static byte[] toByteArray(String s) {
	return DatatypeConverter.parseHexBinary(s);
	}
}