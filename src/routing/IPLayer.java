package routing;


import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	private List<Entry> staticRoutingTable = new ArrayList<>();

	public IPLayer(String pName) {
		pLayerName = pName;
	}

	public synchronized boolean Send(byte[] input, int length) {
		// Not Implemented
		return true;
	}
	
	public byte[] RemoveIPHeader(byte[] input, int length) {
		byte[] buf = new byte[length - 20];

		for (int i = 20; i < length; i++)
			buf[i-20] = input[i];

		return buf;
	}

	public synchronized boolean Receive(byte[] input) {
		// Not Implemented
		return true;
	}
	
	public synchronized boolean Receive(byte[] input, int deviceNum) {
		if(!CheckAddress(input, deviceNum)) return false;
		String deviceIP = NILayer.deviceData.get(deviceNum).ipString;
		String dstString = extractDstIP(input);
		
		// Route only if myIP != dstIP
		if(!deviceIP.equals(dstString)) {
			
			// for all element
			for(int i = 0; i < staticRoutingTable.size(); i++) {
				Entry entry = staticRoutingTable.get(i);
				
				byte[] dstByte = AddressTranslator.stringToByteIP(dstString);
				byte[] maskbyte = AddressTranslator.stringToByteIP(entry.netmask);
				byte[] dstNet = masking(dstByte, maskbyte);
				String dstNetString = AddressTranslator.byteToStringIP(dstNet);
				
				String nextHop = null;
				if(entry.destination.equals(dstNetString)) {
					if(entry.gateway.equals("connected")) 		nextHop = dstString;
					else 										nextHop = entry.gateway;
				}
				else if(entry.destination.equals("0.0.0.0"))	nextHop = entry.gateway;
				
				if(nextHop != null) {
					((ARPLayer)GetUnderLayer()).Send(input, Integer.parseInt(entry.interface_), nextHop);
					return true;
				}
			}
		}
		
		return true;
	}
	
	private byte[] masking(byte[] address, byte[] mask) {
		byte[] masked = new byte[4];
		for(int i = 0; i < 4; i++)
			masked[i] = (byte) (address[i] & mask[i]);
		
		return masked;
	}
	
	private String extractDstIP(byte[] input) {
    	byte[] addr = new byte[4];
        String addr_str = new String();

        for (int i = 0; i < 4; ++i)
            addr[i] = input[i + 16];

        addr_str += Byte.toUnsignedInt(addr[0]);
        for (int j = 1; j < 4; ++j) {
        	addr_str += ".";
        	addr_str += Byte.toUnsignedInt(addr[j]);
        }

        return addr_str;
    }
	
	public boolean CheckAddress(byte[] packet, int deviceNum) {
		
		// srcaddr == my ip addr -> false
		for (int i = 0; i < 4; i++) {
			if(packet[i+12] != NILayer.deviceData.get(deviceNum).ipByte[i]) break;
			if(i == 5) return false;
		}
		
		return true;
	}
	
	@Override
	public String GetLayerName() {
		// TODO Auto-generated method stub
		return pLayerName;
	}

	@Override
	public BaseLayer GetUnderLayer() {
		// TODO Auto-generated method stub
		if (p_UnderLayer == null)
			return null;
		return p_UnderLayer;
	}

	@Override
	public BaseLayer GetUpperLayer(int nindex) {
		// TODO Auto-generated method stub
		if (nindex < 0 || nindex > nUpperLayerCount || nUpperLayerCount < 0)
			return null;
		return p_aUpperLayer.get(nindex);
	}

	@Override
	public void SetUnderLayer(BaseLayer pUnderLayer) {
		// TODO Auto-generated method stub
		if (pUnderLayer == null)
			return;
		this.p_UnderLayer = pUnderLayer;
	}

	@Override
	public void SetUpperLayer(BaseLayer pUpperLayer) {
		// TODO Auto-generated method stub
		if (pUpperLayer == null)
			return;
		this.p_aUpperLayer.add(nUpperLayerCount++, pUpperLayer);
		// nUpperLayerCount++;

	}

	@Override
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);
	}
	
	public void removeEntry(int index) throws NoSuchAlgorithmException {
		this.staticRoutingTable.remove(index);
	}
	
	public void addEntry(String[] value) throws NoSuchAlgorithmException {
		this.staticRoutingTable.add(new Entry(value));
	}
	
	class Entry {
    	String destination;
    	String netmask;
    	String gateway;
    	String flag;
    	String interface_;
    	String metric;
    	
    	public Entry(String[] value) {
    		this.destination = value[0];
    		this.netmask = value[1];
    		this.gateway = value[2];
    		this.flag = value[3];
    		this.interface_ = value[4];
    		this.metric = value[5];
    	}
    }
}
