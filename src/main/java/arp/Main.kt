package arp

import org.pcap4j.core.BpfProgram
import org.pcap4j.core.PcapNetworkInterface
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.*
import org.pcap4j.packet.namednumber.*
import org.pcap4j.util.ByteArrays
import org.pcap4j.util.MacAddress
import java.net.InetAddress

fun main() {
    Pcaps.findAllDevs()[0].also {
        it.openLive(64 * 1024, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10).apply {
            setFilter("arp and ether dst " + Pcaps.toBpfString(MacAddress.ETHER_BROADCAST_ADDRESS), BpfProgram.BpfCompileMode.OPTIMIZE)
            loop(-1) { packet: Packet ->
                if (packet.contains(ArpPacket::class.java)) {
                    val arp = packet.get(ArpPacket::class.java)
                    if (arp.header.operation == ArpOperation.REQUEST) {
                        sendReply(it, arp.header.srcProtocolAddr, arp.header.srcHardwareAddr, arp.header.dstProtocolAddr)
                    }
                }
            }
        }
    }
}

fun sendReply(nInterface: PcapNetworkInterface, srcIp: InetAddress, srcMac: MacAddress, destIp: InetAddress) {
    val arp = ArpPacket.Builder()
            .srcHardwareAddr(MacAddress.getByAddress(nInterface.linkLayerAddresses[0].address))
            .srcProtocolAddr(destIp)
            .dstHardwareAddr(srcMac)
            .dstProtocolAddr(srcIp)
            .hardwareType(ArpHardwareType.ETHERNET)
            .protocolType(EtherType.IPV4)
            .hardwareAddrLength(MacAddress.SIZE_IN_BYTES.toByte())
            .protocolAddrLength(ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES.toByte())
            .operation(ArpOperation.REPLY)

    EthernetPacket.Builder()
            .dstAddr(srcMac)
            .srcAddr(MacAddress.getByAddress(nInterface.linkLayerAddresses[0].address))
            .type(EtherType.ARP)
            .payloadBuilder(arp)
            .paddingAtBuild(true)
            .build()
            .also {
                nInterface.openLive(64 * 1024, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10).apply {
                    sendPacket(it)
                    close()
                }
            }
}