package routing;

import java.awt.Color;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.UIManager;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

import org.jnetpcap.PcapIf;


public class Dlg extends JFrame implements BaseLayer {
	public int nUpperLayerCount = 0;
	public String pLayerName = null;
	public BaseLayer p_UnderLayer = null;
	public ArrayList<BaseLayer> p_aUpperLayer = new ArrayList<BaseLayer>();
	BaseLayer UnderLayer;

	private static LayerManager m_LayerMgr = new LayerManager();

	DefaultTableModel staticRoutingTableModel;
	Vector<String> staticRoutingTableColumns = new Vector<String>();
	Vector<String> staticRoutingTableRows = new Vector<String>();
	
	DefaultTableModel ARPCacheTableModel;
	Vector<String> ARPCacheTableColumns = new Vector<String>();
	Vector<String> ARPCacheTableRows = new Vector<String>();
	
	DefaultTableModel proxyCacheTableModel;
	Vector<String> proxyCacheTableColumns = new Vector<String>();
	Vector<String> proxyCacheTableRows = new Vector<String>();
	
	JTable staticRoutingTable;
	JTable ARPCacheTable;
	JTable proxyARPTable;
	
	Container contentPane;

	JButton staticRoutingTableAddButton;
	JButton staticRoutingTableDeleteButton;
	JButton ARPCacheTableDeleteButton;
	JButton proxyARPTableAddButton;
	JButton proxyARPTableDeleteButton;
	JButton startLayerSettingButton;


	public static void main(String[] args) throws SocketException {
		// TODO Auto-generated method stub
		m_LayerMgr.AddLayer(new NILayer("NI"));
		m_LayerMgr.AddLayer(new EthernetLayer("Eth"));
		m_LayerMgr.AddLayer(new ARPLayer("ARP"));
		m_LayerMgr.AddLayer(new IPLayer("IP"));
		m_LayerMgr.AddLayer(new Dlg("GUI"));
		m_LayerMgr.ConnectLayers(" NI ( *Eth ( *ARP +IP ( *GUI ) ) )");
		m_LayerMgr.GetLayer("IP").SetUnderLayer(m_LayerMgr.GetLayer("ARP"));
	}

	public Dlg(String pName) throws SocketException {
		pLayerName = pName;

		// Preprocess
		staticRoutingTableColumns.addElement("Destination");
		staticRoutingTableColumns.addElement("NetMask");
		staticRoutingTableColumns.addElement("Gateway");
		staticRoutingTableColumns.addElement("Flag");
		staticRoutingTableColumns.addElement("Interface");
		staticRoutingTableColumns.addElement("Metric");
		
		ARPCacheTableColumns.addElement("IP Address");
		ARPCacheTableColumns.addElement("Ethernet Address");
		ARPCacheTableColumns.addElement("Interface");
		ARPCacheTableColumns.addElement("Flag");
		
		proxyCacheTableColumns.addElement("IP Address");
		proxyCacheTableColumns.addElement("Ehternet Address");
		proxyCacheTableColumns.addElement("Interface");
		
		staticRoutingTableModel = new DefaultTableModel(staticRoutingTableColumns, 0);
		ARPCacheTableModel = new DefaultTableModel(ARPCacheTableColumns, 0);
		proxyCacheTableModel = new DefaultTableModel(proxyCacheTableColumns, 0);
		
		
		// Window
		setTitle("Form1");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(250, 250, 1100, 500);
		contentPane = new JPanel();
		((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		pLayerName = pName;

		
		
		// Static Routing Table
		JPanel staticRoutingPanel = new JPanel();
		staticRoutingPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Static Routing Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		staticRoutingPanel.setBounds(10, 5, 600, 425);
		contentPane.add(staticRoutingPanel);
		staticRoutingPanel.setLayout(null);

		staticRoutingTable = new JTable(staticRoutingTableModel);
		staticRoutingTable.setBounds(0, 0, 580, 355);
		staticRoutingTable.setShowGrid(false);

		JScrollPane staticRoutingTableScrollPane = new JScrollPane(staticRoutingTable);
		staticRoutingTableScrollPane.setBounds(10, 15, 580, 355);
		staticRoutingPanel.add(staticRoutingTableScrollPane);
		
		staticRoutingTableAddButton = new JButton("Add");
		staticRoutingTableAddButton.setBounds(420, 380, 80, 30);
		staticRoutingTableAddButton.addActionListener(new setAddressListener());
		staticRoutingPanel.add(staticRoutingTableAddButton);

		staticRoutingTableDeleteButton = new JButton("Delete");
		staticRoutingTableDeleteButton.setBounds(510, 380, 80, 30);
		staticRoutingTableDeleteButton.addActionListener(new setAddressListener());
		staticRoutingPanel.add(staticRoutingTableDeleteButton);
		
		startLayerSettingButton = new JButton("Layer start");
		startLayerSettingButton.setBounds(10, 380, 100, 30);
		startLayerSettingButton.addActionListener(new restartLayerListener());
		staticRoutingPanel.add(startLayerSettingButton);
		
		// ARP Cache Table
		JPanel ARPCachePanel = new JPanel();
		ARPCachePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ARPCachePanel.setBounds(620, 5, 450, 210);
		contentPane.add(ARPCachePanel);
		ARPCachePanel.setLayout(null);


		ARPCacheTable = new JTable(ARPCacheTableModel);
		ARPCacheTable.setBounds(0, 0, 580, 355);
		ARPCacheTable.setShowGrid(false);

		JScrollPane ARPCacheTableScrollPane = new JScrollPane(ARPCacheTable);
		ARPCacheTableScrollPane.setBounds(10, 15, 430, 150);
		ARPCachePanel.add(ARPCacheTableScrollPane);
		
		ARPCacheTableDeleteButton = new JButton("Delete");
		ARPCacheTableDeleteButton.setBounds(360, 170, 80, 30);
		ARPCacheTableDeleteButton.addActionListener(new setAddressListener());
		ARPCachePanel.add(ARPCacheTableDeleteButton);
		
		
		
		// Proxy ARP Table
		JPanel ProxyARPPanel = new JPanel();
		ProxyARPPanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "Proxy ARP Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ProxyARPPanel.setBounds(620, 220, 450, 210);
		contentPane.add(ProxyARPPanel);
		ProxyARPPanel.setLayout(null);
		
		proxyARPTable = new JTable(proxyCacheTableModel);
		proxyARPTable.setBounds(0, 0, 580, 355);
		proxyARPTable.setShowGrid(false);

		JScrollPane proxtARPTableScrollPane = new JScrollPane(proxyARPTable);
		proxtARPTableScrollPane.setBounds(10, 15, 430, 150);
		ProxyARPPanel.add(proxtARPTableScrollPane);
		
		proxyARPTableAddButton = new JButton("Add");
		proxyARPTableAddButton.setBounds(270, 170, 80, 30);
		proxyARPTableAddButton.addActionListener(new setAddressListener());
		ProxyARPPanel.add(proxyARPTableAddButton);
		
		proxyARPTableDeleteButton = new JButton("Delete");
		proxyARPTableDeleteButton.setBounds(360, 170, 80, 30);
		proxyARPTableDeleteButton.addActionListener(new setAddressListener());
		ProxyARPPanel.add(proxyARPTableDeleteButton);


		setVisible(true);
		setResizable(false);
	}
	
	class restartLayerListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == startLayerSettingButton) {
				((NILayer)m_LayerMgr.GetLayer("NI")).activateAllAdapter();
				
			}
		}
	}

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == staticRoutingTableAddButton) {
				new StaticRouteAddDlg();
			}
			else if(e.getSource() == staticRoutingTableDeleteButton) {
				int[] selected = staticRoutingTable.getSelectedRows();
				for(int i = selected.length - 1; i >= 0; i--) {
					try {
						IPLayer ip = ((IPLayer) m_LayerMgr.GetLayer("IP"));
						ip.removeEntry(selected[i]);
					} catch (NoSuchAlgorithmException e1) {
						e1.printStackTrace();
					}
					staticRoutingTableModel.removeRow(selected[i]);
				}
			}
			else if(e.getSource() == ARPCacheTableDeleteButton) {
				int[] selected = ARPCacheTable.getSelectedRows();
				for(int i = selected.length - 1; i >= 0; i--) {
					String str = ARPCacheTableModel.getValueAt(selected[i], 0).toString();
					
					try {
						ARPLayer arp = ((ARPLayer) m_LayerMgr.GetLayer("ARP"));
						arp.removeARPCacheEntry(str);
					} catch (NoSuchAlgorithmException e1) {
						e1.printStackTrace();
					}
					ARPCacheTableModel.removeRow(selected[i]);
				}
			}
			else if(e.getSource() == proxyARPTableAddButton) {
				new ProxyARPAddDlg();
			}
			else if(e.getSource() == proxyARPTableDeleteButton) {
				int[] selected = proxyARPTable.getSelectedRows();
				for(int i = selected.length - 1; i >= 0; i--) {
					String str = proxyCacheTableModel.getValueAt(selected[i], 0).toString();
					
					try {
						ARPLayer arp = ((ARPLayer) m_LayerMgr.GetLayer("ARP"));
						arp.removeProxyEntry(str);
					} catch (NoSuchAlgorithmException e1) {
						e1.printStackTrace();
					}
					proxyCacheTableModel.removeRow(selected[i]);
				}
			}
		}
	}

	public synchronized boolean Receive(byte[] input) {
		// Not Implemented
		return true;
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
	
	public synchronized void updateStaticRoutingTableRow(String[] value) {
		staticRoutingTableRows = new Vector<String>();
		staticRoutingTableRows.addElement(value[0]);
		staticRoutingTableRows.addElement(value[1]);
		staticRoutingTableRows.addElement(value[2]);
		staticRoutingTableRows.addElement(value[3]);
		staticRoutingTableRows.addElement(value[4]);
		staticRoutingTableRows.addElement(value[5]);
		staticRoutingTableModel.addRow(staticRoutingTableRows);
	}
	
	public synchronized void updateARPCacheTableRow(String[] value) {
		ARPCacheTableRows = new Vector<String>();
		ARPCacheTableRows.addElement(value[0]);
		ARPCacheTableRows.addElement(value[1]);
		ARPCacheTableRows.addElement(value[2]);
		ARPCacheTableRows.addElement(value[3]);
		ARPCacheTableModel.addRow(ARPCacheTableRows);
	}
	
	public synchronized void removeARPCacheTableRow(String addr) {
		for(int i = 0; i < ARPCacheTableModel.getRowCount(); i++) {
			if(ARPCacheTableModel.getValueAt(i, 0).toString().equals(addr)) {
				ARPCacheTableModel.removeRow(i); 
				break;
			}
		}
	}
	
	public synchronized void updateProxyARPTableRow(String[] value) {
		proxyCacheTableRows = new Vector<String>();
		proxyCacheTableRows.addElement(value[0]);
		proxyCacheTableRows.addElement(value[1]);
		proxyCacheTableRows.addElement(value[2]);
		proxyCacheTableModel.addRow(proxyCacheTableRows);
	}

	
	private class StaticRouteAddDlg extends JFrame {
		
		Container contentPane;
		
		JTextField destinationInputField;
		JTextField netmaskInputField;
		JTextField gatewayInputField;
		
		JCheckBox upCheckBox;
		JCheckBox gatewayCheckBox;
		JCheckBox hostCheckBox;
		
		JComboBox<String> interfaceComboBox;
		
		JButton addButton;
		JButton cancelButton;
		
		
		public StaticRouteAddDlg() {
			setTitle("Form2");
			setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
			setBounds(250, 250, 400, 300);
			contentPane = new JPanel();
			((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
			setContentPane(contentPane);
			contentPane.setLayout(null);
			
			// Destination
			JLabel destinationlbl = new JLabel("Destination");
			destinationlbl.setBounds(20, 25, 100, 30);
			contentPane.add(destinationlbl);
			destinationlbl.setFont(destinationlbl.getFont().deriveFont(18.0f));
			
			destinationInputField = new JTextField();
			destinationInputField.setBounds(130, 25, 230, 30);
			contentPane.add(destinationInputField);
			
			
			// Network
			JLabel netmasklbl = new JLabel("NetMask");
			netmasklbl.setBounds(20, 60, 100, 30);
			contentPane.add(netmasklbl);
			netmasklbl.setFont(netmasklbl.getFont().deriveFont(18.0f));
			
			netmaskInputField = new JTextField();
			netmaskInputField.setBounds(130, 60, 230, 30);
			contentPane.add(netmaskInputField);
			
			
			// Gateway
			JLabel gatewaylbl = new JLabel("Gateway");
			gatewaylbl.setBounds(20, 95, 100, 30);
			contentPane.add(gatewaylbl);
			gatewaylbl.setFont(gatewaylbl.getFont().deriveFont(18.0f));
			
			gatewayInputField = new JTextField();
			gatewayInputField.setBounds(130, 95, 230, 30);
			contentPane.add(gatewayInputField);
			
			
			// Flag
			JLabel flaglbl = new JLabel("Flag");
			flaglbl.setBounds(20, 130, 100, 30);
			contentPane.add(flaglbl);
			flaglbl.setFont(flaglbl.getFont().deriveFont(18.0f));
			
			upCheckBox = new JCheckBox("UP", false);
			upCheckBox.setBounds(130, 130, 45, 30);
			contentPane.add(upCheckBox);
			
			gatewayCheckBox = new JCheckBox("Gateway", false);
			gatewayCheckBox.setBounds(180, 130, 75, 30);
			contentPane.add(gatewayCheckBox);
			
			hostCheckBox = new JCheckBox("Host", false);
			hostCheckBox.setBounds(260, 130, 55, 30);
			contentPane.add(hostCheckBox);
			
			
			// Interface
			JLabel interfacelbl = new JLabel("Interface");
			interfacelbl.setBounds(20, 165, 100, 30);
			contentPane.add(interfacelbl);
			interfacelbl.setFont(interfacelbl.getFont().deriveFont(18.0f));
			
			interfaceComboBox = new JComboBox<>();
			
			List<PcapIf> l = ((NILayer) m_LayerMgr.GetLayer("NI")).m_pAdapterList;
			for (int i = 0; i < l.size(); i++)
				interfaceComboBox.addItem(l.get(i).getDescription() + " : " + l.get(i).getName());
			
			interfaceComboBox.setBounds(130, 165, 230, 30);
			interfaceComboBox.addActionListener(new setAddressListener());
			contentPane.add(interfaceComboBox);// src address
			
			
			// Buttons
			addButton = new JButton("Add");
			addButton.setBounds(120, 210, 80, 30);
			addButton.addActionListener(new setAddressListener());
			contentPane.add(addButton);
			
			cancelButton = new JButton("Cancel");
			cancelButton.setBounds(210, 210, 80, 30);
			cancelButton.addActionListener(new setAddressListener());
			contentPane.add(cancelButton);
			
			
			setDefaultCloseOperation(0);
			setVisible(true);
			setResizable(false);
		}
		
		class setAddressListener implements ActionListener {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == cancelButton) {
					dispose();
				}
				else if(e.getSource() == addButton) {
					String[] value = new String[6];
					value[0] = destinationInputField.getText();
					value[1] = netmaskInputField.getText();
					value[2] = gatewayInputField.getText();
					
					value[3] = "";
					value[3] += upCheckBox.isSelected() ? "U" : "";
					value[3] += gatewayCheckBox.isSelected() ? "G" : "";
					value[3] += hostCheckBox.isSelected() ? "H" : "";
					
					value[4] = Integer.toString(interfaceComboBox.getSelectedIndex());
					value[5] = "-";
					
					try {
						IPLayer ip = ((IPLayer) m_LayerMgr.GetLayer("IP"));
						ip.addEntry(value);
					} catch (NoSuchAlgorithmException e1) {
						e1.printStackTrace();
					}
					
					updateStaticRoutingTableRow(value);
					dispose();
				}
			}
		}
	}
	
	private class ProxyARPAddDlg extends JFrame {
		
		Container contentPane;
		
		JTextField ipAddressInputField;
		JTextField macAddressInputField;
		
		JComboBox<String> interfaceComboBox;
		
		JButton addButton;
		JButton cancelButton;
		
		
		public ProxyARPAddDlg() {
			setTitle("Form3");
			setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
			setBounds(250, 250, 400, 300);
			contentPane = new JPanel();
			((JComponent) contentPane).setBorder(new EmptyBorder(5, 5, 5, 5));
			setContentPane(contentPane);
			contentPane.setLayout(null);
			
			// Destination
			JLabel destinationlbl = new JLabel("IP");
			destinationlbl.setBounds(20, 25, 100, 30);
			contentPane.add(destinationlbl);
			destinationlbl.setFont(destinationlbl.getFont().deriveFont(18.0f));
			
			ipAddressInputField = new JTextField();
			ipAddressInputField.setBounds(130, 25, 230, 30);
			contentPane.add(ipAddressInputField);
			
			
			// Network
			JLabel netmasklbl = new JLabel("MAC");
			netmasklbl.setBounds(20, 60, 100, 30);
			contentPane.add(netmasklbl);
			netmasklbl.setFont(netmasklbl.getFont().deriveFont(18.0f));
			
			macAddressInputField = new JTextField();
			macAddressInputField.setBounds(130, 60, 230, 30);
			contentPane.add(macAddressInputField);
			
			
			// Interface
			JLabel interfacelbl = new JLabel("Interface");
			interfacelbl.setBounds(20, 95, 100, 30);
			contentPane.add(interfacelbl);
			interfacelbl.setFont(interfacelbl.getFont().deriveFont(18.0f));
			
			interfaceComboBox = new JComboBox<>();
			
			List<PcapIf> l = ((NILayer) m_LayerMgr.GetLayer("NI")).m_pAdapterList;
			for (int i = 0; i < l.size(); i++)
				interfaceComboBox.addItem(l.get(i).getDescription() + " : " + l.get(i).getName());
			
			interfaceComboBox.setBounds(130, 95, 230, 30);
			interfaceComboBox.addActionListener(new setAddressListener());
			contentPane.add(interfaceComboBox);// src address
			
			
			// Buttons
			addButton = new JButton("Add");
			addButton.setBounds(120, 210, 80, 30);
			addButton.addActionListener(new setAddressListener());
			contentPane.add(addButton);
			
			cancelButton = new JButton("Cancel");
			cancelButton.setBounds(210, 210, 80, 30);
			cancelButton.addActionListener(new setAddressListener());
			contentPane.add(cancelButton);
			
			
			setDefaultCloseOperation(0);
			setVisible(true);
			setResizable(false);
		}
		
		class setAddressListener implements ActionListener {
			@Override
			public void actionPerformed(ActionEvent e) {
				if(e.getSource() == cancelButton) {
					dispose();
				}
				else if(e.getSource() == addButton) {
					String[] value = new String[3];
					value[0] = ipAddressInputField.getText();
					value[1] = macAddressInputField.getText();
					value[2] = Integer.toString(interfaceComboBox.getSelectedIndex());
					
					try {
						ARPLayer arp = ((ARPLayer) m_LayerMgr.GetLayer("ARP"));
						arp.addProxyEntry(value);
					} catch (NoSuchAlgorithmException e1) {
						e1.printStackTrace();
					}
					
					updateProxyARPTableRow(value);
					dispose();
				}
			}
		}
	}
}
