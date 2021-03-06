package routing;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

public class ARPLayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	private Map<String, Entry> cacheTable = new HashMap<>();
	private Map<String, Entry> ProxyARPCacheTable = new HashMap<>();

	private _ARP_Packet m_sHeader = new _ARP_Packet();

	private class _ARP_Packet {
		_MAC_ADDR src_mac_addr;
		_MAC_ADDR dst_mac_addr;
		_IP_ADDR src_ip_addr;
		_IP_ADDR dst_ip_addr;

		byte[] hardware_type;
		byte[] protocol_type;
		byte hardware_addr_len;
		byte protocol_addr_len;
		byte[] opcode;

		public _ARP_Packet() {
			src_mac_addr = new _MAC_ADDR();
			dst_mac_addr = new _MAC_ADDR();
			src_ip_addr = new _IP_ADDR();
			dst_ip_addr = new _IP_ADDR();

			hardware_type = new byte[2];
			protocol_type = new byte[2];
			hardware_addr_len = (byte) 0x00;
			protocol_addr_len = (byte) 0x00;
			opcode = new byte[2];
		}

		private class _MAC_ADDR {
			private byte[] addr = new byte[6];

			public _MAC_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
				this.addr[4] = (byte) 0x00;
				this.addr[5] = (byte) 0x00;
			}
		}

		private class _IP_ADDR {
			private byte[] addr = new byte[4];

			public _IP_ADDR() {
				this.addr[0] = (byte) 0x00;
				this.addr[1] = (byte) 0x00;
				this.addr[2] = (byte) 0x00;
				this.addr[3] = (byte) 0x00;
			}
		}

	}

	public ARPLayer(String pName) {
		pLayerName = pName;
		setHeader();
		ARPRepeatThread thread = new ARPRepeatThread(this);
		Thread obj = new Thread(thread);
		obj.start();
	}

	public void setHeader() {
		m_sHeader.hardware_type[0] = (byte) 0x00;
		m_sHeader.hardware_type[1] = (byte) 0x01;
		m_sHeader.protocol_type[0] = (byte) 0x08;
		m_sHeader.protocol_type[1] = (byte) 0x00;
		m_sHeader.hardware_addr_len = (byte) 0x06;
		m_sHeader.protocol_addr_len = (byte) 0x04;
		m_sHeader.opcode[0] = (byte) 0x00;
		m_sHeader.opcode[1] = (byte) 0x01;
		m_sHeader.dst_mac_addr.addr[0] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[1] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[2] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[3] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[4] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[5] = (byte) 0x00;
	}

	public void setHeader(String dstIP, int deviceNum) {
		StringTokenizer st = new StringTokenizer(dstIP, "\\.");

		m_sHeader.src_mac_addr.addr[0] = NILayer.deviceData.get(deviceNum).macByte[0];
		m_sHeader.src_mac_addr.addr[1] = NILayer.deviceData.get(deviceNum).macByte[1];
		m_sHeader.src_mac_addr.addr[2] = NILayer.deviceData.get(deviceNum).macByte[2];
		m_sHeader.src_mac_addr.addr[3] = NILayer.deviceData.get(deviceNum).macByte[3];
		m_sHeader.src_mac_addr.addr[4] = NILayer.deviceData.get(deviceNum).macByte[4];
		m_sHeader.src_mac_addr.addr[5] = NILayer.deviceData.get(deviceNum).macByte[5];
		m_sHeader.src_ip_addr.addr[0] = NILayer.deviceData.get(deviceNum).ipByte[0];
		m_sHeader.src_ip_addr.addr[1] = NILayer.deviceData.get(deviceNum).ipByte[1];
		m_sHeader.src_ip_addr.addr[2] = NILayer.deviceData.get(deviceNum).ipByte[2];
		m_sHeader.src_ip_addr.addr[3] = NILayer.deviceData.get(deviceNum).ipByte[3];

		m_sHeader.dst_ip_addr.addr[0] = (byte) Integer.parseInt(st.nextToken());
		m_sHeader.dst_ip_addr.addr[1] = (byte) Integer.parseInt(st.nextToken());
		m_sHeader.dst_ip_addr.addr[2] = (byte) Integer.parseInt(st.nextToken());
		m_sHeader.dst_ip_addr.addr[3] = (byte) Integer.parseInt(st.nextToken());
		m_sHeader.dst_mac_addr.addr[0] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[1] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[2] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[3] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[4] = (byte) 0x00;
		m_sHeader.dst_mac_addr.addr[5] = (byte) 0x00;
		m_sHeader.opcode[1] = 0x01;
	}

	private byte[] ObjToByte() {
		byte[] buf = new byte[28];

		buf[0] = m_sHeader.hardware_type[0];
		buf[1] = m_sHeader.hardware_type[1];
		buf[2] = m_sHeader.protocol_type[0];
		buf[3] = m_sHeader.protocol_type[1];
		buf[4] = m_sHeader.hardware_addr_len;
		buf[5] = m_sHeader.protocol_addr_len;
		buf[6] = m_sHeader.opcode[0];
		buf[7] = m_sHeader.opcode[1];
		buf[8] = m_sHeader.src_mac_addr.addr[0];
		buf[9] = m_sHeader.src_mac_addr.addr[1];
		buf[10] = m_sHeader.src_mac_addr.addr[2];
		buf[11] = m_sHeader.src_mac_addr.addr[3];
		buf[12] = m_sHeader.src_mac_addr.addr[4];
		buf[13] = m_sHeader.src_mac_addr.addr[5];
		buf[14] = m_sHeader.src_ip_addr.addr[0];
		buf[15] = m_sHeader.src_ip_addr.addr[1];
		buf[16] = m_sHeader.src_ip_addr.addr[2];
		buf[17] = m_sHeader.src_ip_addr.addr[3];
		buf[18] = m_sHeader.dst_mac_addr.addr[0];
		buf[19] = m_sHeader.dst_mac_addr.addr[1];
		buf[20] = m_sHeader.dst_mac_addr.addr[2];
		buf[21] = m_sHeader.dst_mac_addr.addr[3];
		buf[22] = m_sHeader.dst_mac_addr.addr[4];
		buf[23] = m_sHeader.dst_mac_addr.addr[5];
		buf[24] = m_sHeader.dst_ip_addr.addr[0];
		buf[25] = m_sHeader.dst_ip_addr.addr[1];
		buf[26] = m_sHeader.dst_ip_addr.addr[2];
		buf[27] = m_sHeader.dst_ip_addr.addr[3];

		return buf;
	}

	public synchronized boolean Send(byte[] input, int length) {
		// Not Implemented
		return true;
	}

	public synchronized boolean Send(byte[] input, int deviceNum, String nextHop) {

		if(ProxyARPCacheTable.containsKey(nextHop)) {
			((EthernetLayer) GetUnderLayer()).Setenet_dstaddr(ProxyARPCacheTable.get(nextHop).mac);
			((EthernetLayer) GetUnderLayer()).Send(input, input.length, deviceNum);
			return true;
		}
		else if (!cacheTable.containsKey(nextHop)) {
			setHeader(nextHop, deviceNum);
			byte[] msg = ObjToByte();
			updateCache(nextHop, new Entry(nextHop, "??-??-??-??-??-??", Integer.toString(deviceNum), "incomplete"));
			((EthernetLayer) GetUnderLayer()).Send(msg, msg.length, deviceNum);
		}
		
		SendThread thread = new SendThread(nextHop, input, deviceNum, this);
		Thread obj = new Thread(thread);
		obj.start();
		return true;
	}

	public synchronized boolean Receive(byte[] input) {
		// Not Implemented
		return true;
	}

	public synchronized boolean Receive(byte[] input, int deviceNum) {
		updateCache(input, deviceNum, "completed");
		if (isRequest(input)) {
			byte[] tmp = {input[14], input[15], input[16], input[17]};
			String dstIP = AddressTranslator.byteToStringIP(tmp);
			setHeader(dstIP, deviceNum);
			for (int i = 0; i < 6; i++)
				m_sHeader.dst_mac_addr.addr[i] = input[8 + i];
			m_sHeader.opcode[1] = 0x02;

			byte[] response = ObjToByte();

			if (isTargetMe(input)) {
				if (ProxyARPCacheTable.containsKey(getDstIPAddrFromARP(input))) {
					response[14] = input[24];
					response[15] = input[25];
					response[16] = input[26];
					response[17] = input[27];
				}
				((EthernetLayer) GetUnderLayer()).Send(response, response.length, deviceNum);
			} 
		}

		return false;
	}

	private boolean isRequest(byte[] input) {
		return (input[6] == 0x00 && input[7] == 0x01);
	}

	private boolean isTargetMe(byte[] input) {
		for (int i = 0; i < 4; i++) {
			if (input[24 + i] != m_sHeader.src_ip_addr.addr[i])
				break;
			if (i == 3)
				return true;
		}

		return false;
	}

	private synchronized void updateCache(String ip, Entry entry) {
		Dlg GUI = (Dlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0);
		String[] value = new String[4];
		value[0] = entry.ip;
		value[1] = entry.mac;
		value[2] = entry.interface_;
		value[3] = entry.flag;
		this.cacheTable.put(ip, entry);
		GUI.updateARPCacheTableRow(value);
	}

	private synchronized void updateCache(byte[] input, int deviceNum, String flag) {
		try {
			String ip = getSrcIPAddrFromARP(input);
			String mac = getSrcMACAddrFromARP(input);
			Dlg GUI = (Dlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0);

			if (this.cacheTable.containsKey(ip)) {
				this.cacheTable.remove(ip);
				GUI.removeARPCacheTableRow(ip);
			}

			Entry entry = new Entry(ip, mac, Integer.toString(deviceNum), flag);
			this.cacheTable.put(ip, entry);

			String[] value = new String[4];
			value[0] = entry.ip;
			value[1] = entry.mac;
			value[2] = entry.interface_;
			value[3] = entry.flag;

			GUI.updateARPCacheTableRow(value);
		} catch (IndexOutOfBoundsException e) {}
	}

	private String getDstIPAddrFromARP(byte[] input) {
		byte[] addr = new byte[4];
		String addr_str = new String();

		for (int i = 0; i < 4; ++i)
			addr[i] = input[i + 24];

		addr_str += Byte.toUnsignedInt(addr[0]);
		for (int j = 1; j < 4; ++j) {
			addr_str += ".";
			addr_str += Byte.toUnsignedInt(addr[j]);
		}

		return addr_str;
	}

	private String getSrcIPAddrFromARP(byte[] input) {
		byte[] addr = new byte[4];
		String addr_str = new String();

		for (int i = 0; i < 4; ++i)
			addr[i] = input[i + 14];

		addr_str += Byte.toUnsignedInt(addr[0]);
		for (int j = 1; j < 4; ++j) {
			addr_str += ".";
			addr_str += Byte.toUnsignedInt(addr[j]);
		}

		return addr_str;
	}

	private String getSrcMACAddrFromARP(byte[] input) {
		byte[] addr = new byte[6];
		String addr_str = new String();

		for (int i = 0; i < 6; ++i)
			addr[i] = input[i + 8];

		addr_str += String.format("%02X", Byte.toUnsignedInt(addr[0]));
		for (int j = 1; j < 6; ++j) {
			addr_str += "-";
			addr_str += String.format("%02X", Byte.toUnsignedInt(addr[j]));
		}

		return addr_str;
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

	public synchronized void SetMAC_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "-");

		for (int i = 0; i < 6; i++)
			m_sHeader.dst_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);

	}

	public synchronized void SetMAC_srcaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, "-");

		for (int i = 0; i < 6; i++)
			m_sHeader.src_mac_addr.addr[i] = (byte) Integer.parseInt(st.nextToken(), 16);

	}

	public synchronized void SetIP_dstaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, ".");

		for (int i = 0; i < 4; i++)
			m_sHeader.dst_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
	}

	public synchronized void SetIP_srcaddr(String address) {
		StringTokenizer st = new StringTokenizer(address, ".");

		for (int i = 0; i < 4; i++)
			m_sHeader.src_ip_addr.addr[i] = (byte) Integer.parseInt(st.nextToken());
	}

	public void addProxyEntry(String[] value) throws NoSuchAlgorithmException {
		this.ProxyARPCacheTable.put(value[0], new Entry(value[0], value[1], value[2], ""));
	}

	public void removeARPCacheEntry(String value) throws NoSuchAlgorithmException {
		this.cacheTable.remove(value);
	}

	public void removeProxyEntry(String value) throws NoSuchAlgorithmException {
		this.ProxyARPCacheTable.remove(value);
	}

	class Entry {
		String ip;
		String mac;
		String interface_;
		String flag;
		int count;
		long createdTime;

		public Entry(String ip, String mac, String interface_, String flag) {
			this.ip = ip;
			this.mac = mac;
			this.interface_ = interface_;
			this.flag = flag;
			this.count = 0;
			this.createdTime = System.currentTimeMillis();
		}
	}

	class SendThread implements Runnable {
		String dst_addr;
		byte[] input;
		int deviceNum;
		ARPLayer arpLayer;

		public SendThread(String dst_addr, byte[] input, int deviceNum, ARPLayer arplayer) {
			this.dst_addr = dst_addr;
			this.input = input;
			this.deviceNum = deviceNum;
			this.arpLayer = arplayer;
		}

		public void run() {
			while (cacheTable.containsKey(dst_addr)) {
				synchronized (arpLayer) {
					Entry entry = cacheTable.get(dst_addr);
					if (entry.flag == "completed") {
						((EthernetLayer) GetUnderLayer()).Setenet_dstaddr(cacheTable.get(dst_addr).mac);
						((EthernetLayer) GetUnderLayer()).Send(input, input.length, deviceNum);
						break;
					} else if (entry.flag == "failed")
						break;
				}
			}
		}

	}

	class ARPRepeatThread implements Runnable {

		ARPLayer arpLayer;
		
		public ARPRepeatThread(ARPLayer arplayer) {
			this.arpLayer = arplayer;
		}

		public void run() {
			while (true) {
				synchronized (arpLayer) {
					for (String str : cacheTable.keySet()) {
						Entry entry = cacheTable.get(str);
						if (entry.flag == "completed") {
							if (System.currentTimeMillis() - entry.createdTime > 1200000) { // 1200000ms == 20 min
								cacheTable.remove(str);
							}
						} else if (entry.flag == "incomplete") {
							if (entry.count == 10000) {
								Dlg GUI = (Dlg) GetUnderLayer().GetUpperLayer(1).GetUpperLayer(0);
								entry.flag = "failed";
								GUI.removeARPCacheTableRow(entry.ip);
							} else {
								int deviceNum = Integer.parseInt(entry.interface_);
								setHeader(entry.ip, deviceNum);
								byte[] msg = ObjToByte();
								entry.count++;
								GetUnderLayer().Send(msg, msg.length);
							}
	
						}
					}
				}
				try {
					Thread.sleep(300);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
