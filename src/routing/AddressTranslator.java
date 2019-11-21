package routing;

import java.util.StringTokenizer;

public class AddressTranslator {
	
	public static byte[] stringToByte(String address) {
		byte[] byteAddr = new byte[4];
		
		StringTokenizer st = new StringTokenizer(address, "\\.");
		for(int i = 0; i < 4; i++)
			byteAddr[i] = (byte) Integer.parseInt(st.nextToken());
		
		return byteAddr;
	}
	
	public static String byteToString(byte[] address) {
		String dstNetString = "";
		dstNetString += String.format("%02x", address[0]) + ".";
		dstNetString += String.format("%02x", address[1]) + ".";
		dstNetString += String.format("%02x", address[2]) + ".";
		dstNetString += String.format("%02x", address[3]);
		
		return dstNetString;
	}
}
