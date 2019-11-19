package routing;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.TextField;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

import org.jnetpcap.PcapAddr;
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
	
	Container contentPane;

	JButton staticRoutingTableAddButton;
	JButton staticRoutingTableDeleteButton;
	JButton ARPCacheTableDeleteButton;
	JButton proxyARPTableAddButton;
	JButton proxyARPTableDeleteButton;


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

		JTable staticRoutingTable = new JTable(staticRoutingTableModel);
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
		
		
		
		// ARP Cache Table
		JPanel ARPCachePanel = new JPanel();
		ARPCachePanel.setBorder(new TitledBorder(UIManager.getBorder("TitledBorder.border"), "ARP Cache Table",
				TitledBorder.LEADING, TitledBorder.TOP, null, new Color(0, 0, 0)));
		ARPCachePanel.setBounds(620, 5, 450, 210);
		contentPane.add(ARPCachePanel);
		ARPCachePanel.setLayout(null);


		JTable ARPCacheTable = new JTable(ARPCacheTableModel);
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
		
		JTable proxyARPTable = new JTable(ARPCacheTableModel);
		proxyARPTable.setBounds(0, 0, 580, 355);
		proxyARPTable.setShowGrid(false);

		JScrollPane proxtARPTableScrollPane = new JScrollPane(proxyARPTable);
		proxtARPTableScrollPane.setBounds(10, 15, 430, 150);
		ProxyARPPanel.add(proxtARPTableScrollPane);
		
		proxyARPTableAddButton = new JButton("Delete");
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

	class setAddressListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			if(e.getSource() == staticRoutingTableAddButton) {
				new StaticAddDlg();
			}
			// Not Implemented
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

	
	private class StaticAddDlg extends JFrame {
		
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
		
		
		public StaticAddDlg() {
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
				// Not Implemented
			}
		}
	}
}
