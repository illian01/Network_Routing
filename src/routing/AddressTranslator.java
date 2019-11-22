package routing;

import java.util.StringTokenizer;

public class AddressTranslator {
	
	public static byte[] stringToByteIP(String address) {
		byte[] byteAddr = new byte[4];
		
		StringTokenizer st = new StringTokenizer(address, "\\.");
		for(int i = 0; i < 4; i++)
			byteAddr[i] = (byte) Integer.parseInt(st.nextToken());
		
		return byteAddr;
	}
	
	public static String byteToStringIP(byte[] address) {
		String stringAddr = "";
		
		stringAddr += Integer.toString(0xFF & address[0]) + ".";
		stringAddr += Integer.toString(0xFF & address[1]) + ".";
		stringAddr += Integer.toString(0xFF & address[2]) + ".";
		stringAddr += Integer.toString(0xFF & address[3]);
		
		return stringAddr;
	}
	
	public static byte[] stringToByteMAC(String address) {
		byte[] byteAddr = new byte[6];
		
		StringTokenizer st = new StringTokenizer(address, "-");
		for(int i = 0; i < 6; i++)
			byteAddr[i] = (byte) Integer.parseInt(st.nextToken(), 16);
		
		return byteAddr;
	}
	
	public static String byteToStringMAC(byte[] address) {
		String dstNetString = "";
		dstNetString += String.format("%02x", address[0]) + "-";
		dstNetString += String.format("%02x", address[1]) + "-";
		dstNetString += String.format("%02x", address[2]) + "-";
		dstNetString += String.format("%02x", address[3]) + "-";
		dstNetString += String.format("%02x", address[4]) + "-";
		dstNetString += String.format("%02x", address[5]);
		
		return dstNetString;
	}
}
