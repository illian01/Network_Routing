package routing;


import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.jnetpcap.PcapAddr;

import routing.ARPLayer.Entry;


public class IPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	
	String string_ip_src = "";

	private Map<String, Entry> staticRoutingTable = new HashMap<>();

	private class _IP {		// HEADER + data 
		_IP_ADDR ip_src;
		_IP_ADDR ip_dst;
		
		byte ip_verlen;
		byte ip_tos;
		byte[] ip_len;
		byte[] ip_id;
		byte[] ip_fragoff;
		byte ip_ttl;
		byte ip_proto;
		byte[] ip_cksum;
		byte[] ip_data;
		
		public _IP() {
			this.ip_src =  new _IP_ADDR();
			this.ip_dst = new _IP_ADDR();
			
			this.ip_verlen = 0x04;
			this.ip_tos = 0x00;
			this.ip_len = new byte[2];
			this.ip_id = new byte[2];
			this.ip_fragoff = new byte[2];
			this.ip_ttl = 0x00;
			this.ip_proto = 0x00;
			this.ip_cksum = new byte[2];
			this.ip_data = null;
		}
		
		private class _IP_ADDR {
			private byte[] addr = new byte[6];
			
			public _IP_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
			}
		}
		
	}

	_IP m_sHeader = new _IP();

	public IPLayer(String pName) {
		
		pLayerName = pName;
		ResetHeader();
	}

	public void ResetHeader() {
		
		for (int i = 0; i < 4; i++) {
			m_sHeader.ip_src.addr[i] =  0x00;
			m_sHeader.ip_dst.addr[i] =  0x00;
		}
		
		m_sHeader.ip_verlen = 0x04;
		m_sHeader.ip_tos = 0x00;
		m_sHeader.ip_len[0] = 0x00;
		m_sHeader.ip_len[1] = 0x00;
		m_sHeader.ip_id[0] = 0x00;
		m_sHeader.ip_id[1] = 0x00;
		m_sHeader.ip_fragoff[0] = 0x00;
		m_sHeader.ip_fragoff[1] = 0x00;
		m_sHeader.ip_ttl = 0x00;
		m_sHeader.ip_proto = 0x00;
		m_sHeader.ip_data = null;
	}
	

	public byte[] ObjToByte(_IP Header, byte[] input, int length) {
		byte[] buf = new byte[length + 20];

		buf[0] = Header.ip_verlen;
		buf[1] = Header.ip_tos;
		buf[2] = Header.ip_len[0];
		buf[3] = Header.ip_len[1];
		buf[4] = Header.ip_id[0];
		buf[5] = Header.ip_id[1];
		buf[6] = Header.ip_fragoff[0];
		buf[7] = Header.ip_fragoff[1];
		buf[8] = Header.ip_ttl;
		buf[9] = Header.ip_proto;
		buf[10] = Header.ip_cksum[0];
		buf[11] = Header.ip_cksum[1];
		
		for (int i = 0; i < 4; i++)
			buf[12 + i] = Header.ip_src.addr[i];
		
		for (int i = 0; i < 4; i++)
			buf[16 + i] = Header.ip_dst.addr[i];

		for (int i = 0; i < length; i++)
			buf[20 + i] = input[i];

		return buf;
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
			for(String key : staticRoutingTable.keySet()) {
				Entry entry = staticRoutingTable.get(key);
				
				byte[] dstByte = AddressTranslator.stringToByte(dstString);
				byte[] maskbyte = AddressTranslator.stringToByte(entry.netmask);
				byte[] dstNet = masking(dstByte, maskbyte);
				String dstNetString = AddressTranslator.byteToString(dstNet);
				
				if(entry.destination.equals(dstNetString)) {
					if(entry.gateway.equals("connected")) {
						// send to connected host
					}
					else {
						// send to gateway
					}
				}
				else if(entry.destination.equals("0.0.0.0")) {
					// send to gateway
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
	
	public void SetIP_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "\\.");

		for(int i = 0; i < 4; i++)
			m_sHeader.ip_dst.addr[i] = (byte) Integer.parseInt(st.nextToken());
	}
	
	public void SetIP_srcaddr(String address) {
		this.string_ip_src = address;
		StringTokenizer st = new StringTokenizer(address, "\\.");
		
		for(int i = 0; i < 4; i++)
			m_sHeader.ip_src.addr[i] = (byte) Integer.parseInt(st.nextToken());
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

	public String GetSrcIPAddr() {
		return this.string_ip_src;
	}
	
	public void removeEntry(String value) throws NoSuchAlgorithmException {
		String id = "";
		id = idGen(value);
		this.staticRoutingTable.remove(id);
	}
	
	public void addEntry(String[] value) throws NoSuchAlgorithmException {
		String id = "";
		for(int i = 0; i < value.length; i++) id += value[i];
		id = idGen(id);
		this.staticRoutingTable.put(id, new Entry(value));
	}
	
	public String idGen(String str) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(str.getBytes());
		byte byteData[] = md.digest();
		StringBuffer sb = new StringBuffer();
		
		for(int i = 0 ; i < byteData.length ; i++)
			sb.append(Integer.toString((byteData[i]&0xff) + 0x100, 16).substring(1));
		String MD5 = sb.toString();

		return MD5;
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
