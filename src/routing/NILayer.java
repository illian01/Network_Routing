package routing;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class NILayer implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();

	int m_iNumAdapter;
	public static List<Pcap> m_AdapterObject = new ArrayList<>();
	public PcapIf device;
	public static List<PcapIf> m_pAdapterList;
	public static List<DeviceData> deviceData = new ArrayList<>();
	StringBuilder errbuf = new StringBuilder();

	static {
		try {
			System.load(new File("jnetpcap.dll").getAbsolutePath());
			System.out.println(new File("jnetpcap.dll").getAbsolutePath());
		} catch (UnsatisfiedLinkError e) {
			System.out.println("Native code library failed to load.\n" + e);
			System.exit(0);
		}
	}
		
	public NILayer(String pName) {
		// TODO Auto-generated constructor stub
		pLayerName = pName;
		m_pAdapterList = new ArrayList<PcapIf>();
		m_iNumAdapter = 0;
		SetAdapterList();
		for (int i = 0; i < m_pAdapterList.size(); i++)
			deviceData.add(new DeviceData(i));
		
	}
	

	public void SetAdapterList() {
		int r = Pcap.findAllDevs(m_pAdapterList, errbuf);
		if (r == Pcap.NOT_OK || m_pAdapterList.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
	}

	public void activateAllAdapter() {
		for (int i = 0; i < m_pAdapterList.size(); i++) {
			SetAdapterNumber(i);
//			deviceData.add(new DeviceData(i));
		}
	}

	public void SetAdapterNumber(int iNum) {
		m_iNumAdapter = iNum;
		PacketStartDriver();
		Receive();
	}

	public void PacketStartDriver() {
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1;
		m_AdapterObject
				.add(Pcap.openLive(m_pAdapterList.get(m_iNumAdapter).getName(), snaplen, flags, timeout, errbuf));
	}

	public synchronized boolean Send(byte[] input, int length) {
		// Not implemented
		return true;
	}

	public synchronized boolean Send(byte[] input, int length, int deviceNum) {
		ByteBuffer buf = ByteBuffer.wrap(input);
		if (m_AdapterObject.get(deviceNum).sendPacket(buf) != Pcap.OK) {
			System.err.println(m_AdapterObject.get(deviceNum).getErr());
			return false;
		}

		return true;
	}

	public boolean Receive() {
		Receive_Thread thread = new Receive_Thread(m_AdapterObject.get(m_iNumAdapter), this.GetUpperLayer(0),
				m_iNumAdapter);
		Thread obj = new Thread(thread);
		obj.start();

		return false;
	}

	class Receive_Thread implements Runnable {
		byte[] data;
		Pcap AdapterObject;
		int deviceNum;
		BaseLayer UpperLayer;

		public Receive_Thread(Pcap m_AdapterObject, BaseLayer m_UpperLayer, int deviceNum) {
			this.AdapterObject = m_AdapterObject;
			this.deviceNum = deviceNum;
			this.UpperLayer = m_UpperLayer;
		}

		public void run() {
			while (true) {
				PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
					public void nextPacket(PcapPacket packet, String user) {
						data = packet.getByteArray(0, packet.size());
						UpperLayer.Receive(data, deviceNum);
					}
				};

				AdapterObject.loop(100000, jpacketHandler, "");
			}
		}
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
	public void SetUpperUnderLayer(BaseLayer pUULayer) {
		this.SetUpperLayer(pUULayer);
		pUULayer.SetUnderLayer(this);

	}

	class DeviceData {
		byte[] macByte;
		byte[] ipByte;
		String macString;
		String ipString;
		boolean isNull = true;

		public DeviceData(int deviceNum) {
			if(NILayer.m_pAdapterList.get(deviceNum).getAddresses().size() == 0) // Device has null Address
				return;	
			String[] token = NILayer.m_pAdapterList.get(deviceNum).getAddresses().get(0).getAddr().toString()
					.split("\\.");
			if (token[0].contains("INET6"))
				return;
			String ipstring = token[0].substring(7, token[0].length()) + "." + token[1] + "." + token[2] + "."
					+ token[3].substring(0, token[3].length() - 1);

			byte[] macbyte = null;
			isNull = false;
			try {
				macbyte = NILayer.m_pAdapterList.get(deviceNum).getHardwareAddress();
			} catch (IOException e) {
				e.printStackTrace();
			}

			String macstring = AddressTranslator.byteToStringMAC(macbyte);
			byte[] ipbyte = AddressTranslator.stringToByteIP(ipstring);

			this.macByte = macbyte;
			this.ipByte = ipbyte;
			this.macString = macstring;
			this.ipString = ipstring;
			
			System.out.println(deviceNum + " : " + ipstring);
		}
	}
}
