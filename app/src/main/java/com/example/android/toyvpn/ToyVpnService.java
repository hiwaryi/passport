/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.android.toyvpn;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.net.NetworkInterface;
import java.util.Enumeration;
import 	java.net.InetAddress;
import 	java.net.SocketException;
import java.util.Scanner;

public class ToyVpnService extends VpnService implements Handler.Callback, Runnable {
    private static final String TAG = "ToyVpnService";

    private Handler mHandler;
    private Thread mThread;

    private ParcelFileDescriptor mInterface;

    private enum TransportProtocol
    {
        TCP(6),
        UDP(17),
        Other(0xFF);

        private int protocolNumber;

        TransportProtocol(int protocolNumber)
        {
            this.protocolNumber = protocolNumber;
        }

        private static TransportProtocol numberToEnum(int protocolNumber)
        {
            if (protocolNumber == 6)
                return TCP;
            else if (protocolNumber == 17)
                return UDP;
            else
                return Other;
        }

        public int getNumber()
        {
            return this.protocolNumber;
        }
    }

//    IPHeader
    public byte version;
    public byte IHL;
    public short typeOfService;
    public int totalLength;

    public int identificationAndFlagsAndFragmentOffset;

    public short TTL;
    private short protocolNum;
    public TransportProtocol protocol;
    public int headerChecksum;

    public InetAddress sourceAddress;
    public InetAddress destinationAddress;

//    TCPHeader

    public int sourcePort;
    public int destinationPort;

    public long sequenceNumber;
    public long acknowledgementNumber;

    public byte dataOffsetAndReserved;
    public int headerLength;
    public byte flags;
    public int window;

    public int checksum;
    public int urgentPointer;

    public byte[] optionsAndPadding;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "onStartCommand: !!!");
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread.interrupt();
        }

        // Start a new session by creating a new thread.
        mThread = new Thread(this, "ToyVpnThread");
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mThread.interrupt();
        }
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return true;
    }

    @Override
    public synchronized void run() {
        Log.i(TAG,"running vpnService");
        try {
            runVpnConnection();
        } catch (Exception e) {
            e.printStackTrace();
            //Log.e(TAG, "Got " + e.toString());
        } finally {
            try {
                mInterface.close();
            } catch (Exception e) {
                // ignore
            }
            mInterface = null;

            mHandler.sendEmptyMessage(R.string.disconnected);
            Log.i(TAG, "Exiting");
        }
    }

    private boolean runVpnConnection() throws Exception {

        configure();

        FileInputStream in = new FileInputStream(mInterface.getFileDescriptor());

        // Allocate the buffer for a single packet.
        ByteBuffer packet = ByteBuffer.allocate(32767);

        // We keep forwarding packets till something goes wrong.
        while (true) {
            // Assume that we did not make any progress in this iteration.
            boolean idle = true;

            // Read the outgoing packet from the input stream.
            int length = in.read(packet.array());
            if (length > 0) {

                Log.i(TAG,"************new packet");

                byte versionAndIHL = packet.get();
                int version = (byte) (versionAndIHL >> 4);
                int IHL = (byte) (versionAndIHL & 0x0F);
                int headerLength = this.IHL << 2;

                int typeOfService = BitUtils.getUnsignedByte(packet.get());
                int totalLength = BitUtils.getUnsignedShort(packet.getShort());

                int identificationAndFlagsAndFragmentOffset = packet.getInt();

                int TTL = BitUtils.getUnsignedByte(packet.get());
                this.protocolNum = BitUtils.getUnsignedByte(packet.get());
                this.protocol = TransportProtocol.numberToEnum(protocolNum);
                this.headerChecksum = BitUtils.getUnsignedShort(packet.getShort());

                byte[] addressBytes = new byte[4];
                packet.get(addressBytes, 0, 4);
                this.sourceAddress = InetAddress.getByAddress(addressBytes);

                packet.get(addressBytes, 0, 4);
                this.destinationAddress = InetAddress.getByAddress(addressBytes);

                // TCP Header
                this.sourcePort = BitUtils.getUnsignedShort(packet.getShort());
                this.destinationPort = BitUtils.getUnsignedShort(packet.getShort());

                this.sequenceNumber = BitUtils.getUnsignedInt(packet.getInt());
                this.acknowledgementNumber = BitUtils.getUnsignedInt(packet.getInt());

                this.dataOffsetAndReserved = packet.get();
                this.headerLength = (this.dataOffsetAndReserved & 0xF0) >> 2;
                this.flags = packet.get();
                this.window = BitUtils.getUnsignedShort(packet.getShort());

                this.checksum = BitUtils.getUnsignedShort(packet.getShort());
                this.urgentPointer = BitUtils.getUnsignedShort(packet.getShort());

                int optionsLength = this.headerLength - 20;
                if (optionsLength > 0)
                {
                    optionsAndPadding = new byte[optionsLength];
                    packet.get(optionsAndPadding, 0, optionsLength);
                }

//                System.exit(-1);
                Log.i(TAG, "runVpnConnection: " + String.format("%02X%n", sourcePort));
                java.lang.Process p = Runtime.getRuntime().exec("cat /proc/net/tcp6");
                Scanner sc = new Scanner(p.getInputStream());
                String cat = new String();
                while((cat = sc.nextLine()) != null){

                    String[] columns = cat.split(" ");
                    String[] port = columns[4].split(":");
                    if(port.length > 1) {
                        int portCheck = Integer.parseInt(port[1], 16);

                        if(portCheck == sourcePort){
                            int uid = Integer.parseInt(columns[10]);
                            PackageManager pm = getPackageManager();
                            String appName = pm.getNameForUid(uid);
                            Log.i(TAG, "runVpnConnection: " + appName);

                            break;
                        }
                    }
                }
//                String[] columns = sc.nextLine().split("\n");
//                String uid = columns[9];

//                int portCheck = Integer.parseInt(columns[1].split(":")[1], 16);
//                Log.i(TAG, Boolean.toString(portCheck == sourcePort));

                while (packet.hasRemaining()) {
//                    Log.i(TAG,""+packet.get());
                    //System.out.print((char) packet.get());
                }
                packet.limit(length);
                //  tunnel.write(packet);
                packet.clear();

                // There might be more outgoing packets.
                idle = false;
            }
            Thread.sleep(50);
        }
    }

    public String getLocalIpAddress()
    {
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                    InetAddress inetAddress = enumIpAddr.nextElement();
                    Log.i(TAG,"****** INET ADDRESS ******");
                    Log.i(TAG,"address: "+inetAddress.getHostAddress());
                    Log.i(TAG,"hostname: "+inetAddress.getHostName());
                    Log.i(TAG,"address.toString(): "+inetAddress.getHostAddress().toString());
                    if (!inetAddress.isLoopbackAddress()) {
                        //IPAddresses.setText(inetAddress.getHostAddress().toString());
                        Log.i(TAG,"IS NOT LOOPBACK ADDRESS: "+inetAddress.getHostAddress().toString());
                        return inetAddress.getHostAddress().toString();
                    } else{
                        Log.i(TAG,"It is a loopback address");
                    }
                }
            }
        } catch (SocketException ex) {
            String LOG_TAG = null;
            Log.e(LOG_TAG, ex.toString());
        }

        return null;
    }

    private void configure() throws Exception {
        // If the old interface has exactly the same parameters, use it!
        if (mInterface != null) {
            Log.i(TAG, "Using the previous interface");
            return;
        }

        Log.i(TAG, "configure: ");

        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();
        builder.setMtu(1500);
        builder.addAddress("10.0.0.2", 24);
        builder.addRoute("0.0.0.0", 0);

        try {
            mInterface.close();
        } catch (Exception e) {
            // ignore
        }

        mInterface = builder.establish();
    }

    private static class BitUtils
    {
        private static short getUnsignedByte(byte value)
        {
            return (short)(value & 0xFF);
        }

        private static int getUnsignedShort(short value)
        {
            return value & 0xFFFF;
        }

        private static long getUnsignedInt(int value)
        {
            return value & 0xFFFFFFFFL;
        }
    }
}