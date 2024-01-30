
import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterfaceAddress;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharsetDecoder;
import java.nio.ByteBuffer;
import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileWriter;
import java.io.IOException;

public class sample {

    public static void main(String args[]) throws Exception {
	int index = 2;
	NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	JpcapCaptor captor = JpcapCaptor.openDevice(devices[index], 4096, false, 5000);

	// decoding bytes captured
	
	ByteBuffer packbbheader = null;
	ByteBuffer packbbdata = null;
	CharBuffer charbuff = null;
	CharsetDecoder csiso8859decoder = Charset.forName("ISO-8859-1").newDecoder();
	CharsetDecoder csusasciidecoder = Charset.forName("US-ASCII").newDecoder();
	CharsetDecoder csutf8decoder = Charset.forName("UTF-8").newDecoder();
	CharsetDecoder csutf16bedecoder = Charset.forName("UTF-16BE").newDecoder();
	CharsetDecoder csutf16ledecoder = Charset.forName("UTF-16LE").newDecoder();
	CharsetDecoder csutf16decoder = Charset.forName("UTF-16").newDecoder();
	Charset iso8859 = StandardCharsets.ISO_8859_1;
	Charset us_ascii = StandardCharsets.US_ASCII;
	Charset utf_16 = StandardCharsets.UTF_16;
	Charset utf_16be = StandardCharsets.UTF_16BE;
	Charset utf_16le = StandardCharsets.UTF_16LE;
	Charset utf_8 = StandardCharsets.UTF_8;
	Charset[] stdcs = {iso8859, us_ascii, utf_16, utf_16, utf_16be, utf_16le, utf_8};
	int i = -1;

	String packdata = new String();
	String packheader = new String();
	CharBuffer packcbdata = null;
	CharBuffer packcbheader = null;
	/*
	FileWriter dumpwrite = new FileWriter(args[0]);
	BufferedReader inread = new BufferedReader(new InputStreamReader(System.in));
	*/
	boolean run = true;
	Packet pack = new Packet();
	pack = captor.getPacket();
	try {
	    while (run) {
		if (pack != null) {
		    packbbheader = ByteBuffer.allocate(pack.header.length);
		    packbbdata = ByteBuffer.allocate(pack.data.length);
		    packbbheader.put(pack.header);
		    packbbdata.put(pack.data);
		    for (i = 0; i < stdcs.length; i++) {
			packcbheader = stdcs[i].decode(packbbheader);
			System.out.println("break");
			System.out.println(packcbheader);
		    }
		    /*
		      System.out.println(packheader);
		      System.out.println();
		      System.out.println(packdata);
		      System.out.println();
		      System.out.println();
		    */
		}
	    }
	} catch (Exception e) {
	    System.out.println("Exception");
	    e.printStackTrace();
	}	
    }


    public static void getSenderTarget(JpcapCaptor captor) throws IOException {
	captor.setFilter("arp", true);
	ARPPacket arppack = (ARPPacket)captor.getPacket();
	System.out.println("Sender IP Address:\t" + arppack.getSenderProtocolAddress());
	System.out.println("Sender HW Address:\t" + arppack.getSenderHardwareAddress());
	System.out.println("Target IP Address:\t" + arppack.getTargetProtocolAddress());
	System.out.println("Target HW Address:\t" + arppack.getTargetHardwareAddress());

    }

    public static void getdevs() throws IOException {
	//for each network interface
	NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	for (int i = 0; i < devices.length; i++) {
	    //print out its name and description
	    System.out.println(i + ": " + devices[i].name + "(" + devices[i].description + ")");

	    //print out its datalink name and description
	    System.out.println(" datalink: " + devices[i].datalink_name + "(" + devices[i].datalink_description + ")");

	    //print out its MAC address
	    System.out.print(" MAC address:");
	    for (byte b : devices[i].mac_address) {
		System.out.print(Integer.toHexString(b&0xff) + ":");
	    }
	    System.out.println();

	    //print out its IP address, subnet mask and broadcast address
	    for (NetworkInterfaceAddress a : devices[i].addresses) {
		System.out.println(" address: " + a.address + " " + a.subnet + " " + a.broadcast);
	    }
	    System.out.println();
	}
    }
}
