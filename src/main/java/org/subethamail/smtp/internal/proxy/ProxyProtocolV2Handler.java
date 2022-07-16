package org.subethamail.smtp.internal.proxy;

import static org.subethamail.smtp.internal.util.HexUtils.toHex;
import com.github.davidmoten.guavamini.Preconditions;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.subethamail.smtp.internal.util.ArrayUtils;
import org.subethamail.smtp.server.Session;

/**
 * Implements {@link ProxyHandler} for <a href="https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt">PROXY
 * protocol V2 binary</a>.
 *
 * @author Diego Salvi
 */
public class ProxyProtocolV2Handler implements ProxyHandler {
    
    private final static Logger log = Logger.getLogger(ProxyProtocolV2Handler.class.getName());
    
    /**
     * Default maximum data length. Standard max data size in 216 for unix socket (two unix address, 108 bytes each).
     * 2048 is reasonable default to host data plus some optional informations.
     */
    private static final int DEFAULT_MAX_DATA_LENGTH = 2048;

    /** Default thread safe instance with maximum data length size 2048. */
    public static final ProxyProtocolV2Handler INSTANCE = new ProxyProtocolV2Handler();

    private static final byte[] PROXY_MAGIC =
            new byte[]{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

    private static final int PROXY_HEADER_SIZE = 16;
    private static final int BYTE_HIGH_4_BITS_SHIFT = 4;
    private static final int BYTE_LOW_4_BITS = 0x0F;

    private static final int IPV4_LEN = 4;
    private static final int IPV6_LEN = 16;

    /**
     * Basic dos "protection" to defend to forged extremly big header size.
     */
    private final int maxDataLength;

    public enum Command {
        LOCAL(0),
        PROXY(1);

        public final int value;

        private Command(int value) {
            this.value = value;
        }
    }

    public enum Family {
        UNSPEC(0),
        INET(1),
        INET6(2),
        UNIX(3);

        public final int value;

        private Family(int value) {
            this.value = value;
        }
    }

    public enum Transport {
        UNSPEC(0),
        STREAM(1),
        DGRAM(2);

        public final int value;

        private Transport(int value) {
            this.value = value;
        }
    }

    /**
     * Creates a new handler with maximum data length 2048. Standard max data size in 216 for unix socket (two unix
     * address, 108 bytes each). 2048 is reasonable default to host data plus some optional informations.
     */
    private ProxyProtocolV2Handler() {
        this(DEFAULT_MAX_DATA_LENGTH);
    }

    public ProxyProtocolV2Handler(int maxDataLength) {
        this.maxDataLength = maxDataLength;
    }

    /**
     * Returns the PROXY protocol v2 prefix size, it can be used to retrieve data from connection and then invoke
     * {@link #isValidPrefix(byte[])}.
     *
     * @return PROXY protocol v2 prefix size
     */
    static int prefixSize() {
        return PROXY_MAGIC.length;
    }

    /**
     * Check if given prefix is a PROXY protocol v2 prefix. Only the prefix will be checked: it doesn't check any other
     * data following the prefix
     *
     * @param prefix byte array prefix to isValidPrefix
     * @return {@code true} if is a PROXY protocol v1 prefix
     */
    boolean isValidPrefix(byte[] prefix) {
        return prefix.length >= PROXY_MAGIC.length // Must accomodate every prefix byte
                && ArrayUtils.equals(PROXY_MAGIC, 0, PROXY_MAGIC.length, prefix, 0, PROXY_MAGIC.length);
    }

    @Override
    public ProxyResult handle(InputStream in, OutputStream out, Session session) throws IOException {

        /*
         * Header as seen on specs
         * struct proxy_hdr_v2 {
         *     uint8_t sig[12];  // hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A
         *     uint8_t ver_cmd;  // protocol version and command
         *     uint8_t fam;      // protocol family and address
         *     uint16_t len;     // number of following bytes part of the header
         * };
         */
        
        log.log(Level.FINE, "(session {0}) Starting PROXY protocol v2 handling", session.getSessionId());
        
        byte[] header = new byte[PROXY_HEADER_SIZE];
        int read = in.read(header);
        if (read != PROXY_HEADER_SIZE) {
            final String headerHex = toHex(header, 0, read);
            log.log(Level.SEVERE, "(session {0}) Failed to fully read PROXY v2 header. Read {1}",
                    new Object[] { session.getSessionId(), headerHex });
            return ProxyResult.FAIL;
        }

        final String headerHex = toHex(header);
        log.log(Level.FINE, "(session {0}) Read header {1}", new Object[] { session.getSessionId(), headerHex });
        
        if (!ArrayUtils.equals(PROXY_MAGIC, 0, PROXY_MAGIC.length, header, 0, PROXY_MAGIC.length)) { 
            final String receivedMagic = toHex(header, 0, PROXY_MAGIC.length);
            log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v2 magic {1} (header: {2})",
                    new Object[] { session.getSessionId(), receivedMagic, headerHex });
            return ProxyResult.FAIL;
        }

        int idx = PROXY_MAGIC.length;
        int versionAndCommand = Byte.toUnsignedInt(header[idx++]);

        int versionbin = versionAndCommand >> BYTE_HIGH_4_BITS_SHIFT;
        if (versionbin != 0x2) {
            log.log(Level.SEVERE, "(session {0}) Usupported PROXY protocol version {1} (header: {2})",
                    new Object[] { session.getSessionId(), versionbin, headerHex });
            return ProxyResult.FAIL;
        }

        int commandbin = versionAndCommand & BYTE_LOW_4_BITS;

        Command command;
        switch (commandbin) {
            case 0x0:
                command = Command.LOCAL;
                break;
            case 0x1:
                command = Command.PROXY;
                break;
            default:
                log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v2 command {1} (header: {2})",
                        new Object[] { session.getSessionId(), commandbin, headerHex });
                return ProxyResult.FAIL;
        }

        int familyAndTransport = Byte.toUnsignedInt(header[idx++]);

        int familybin = familyAndTransport >> BYTE_HIGH_4_BITS_SHIFT;

        Family family;
        switch (familybin) {
            case 0x0:
                family = Family.UNSPEC;
                break;
            case 0x1:
                family = Family.INET;
                break;
            case 0x2:
                family = Family.INET6;
                break;
            case 0x3:
                family = Family.UNIX;
                break;
            default:
                log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v2 family {1} (header: {2})",
                        new Object[] { session.getSessionId(), familybin, headerHex });
                return ProxyResult.FAIL;
        }

        int transportbin = familyAndTransport & BYTE_LOW_4_BITS;

        Transport transport;
        switch (transportbin) {
            case 0:
                transport = Transport.UNSPEC;
                break;
            case 1:
                transport = Transport.STREAM;
                break;
            case 2:
                transport = Transport.DGRAM;
                break;
            default:
                log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v2 transport {1} (header: {2})",
                        new Object[] { session.getSessionId(), transportbin, headerHex });
                return ProxyResult.FAIL;
        }

        /* Reads a "unsigned" short
         */
        int len = ((int) header[idx++] << Byte.SIZE | (int) header[idx++]) & 0xffff;

        if (len > maxDataLength) {
            log.log(Level.SEVERE, "(session {0}) Invalid PROXY protocol v2 length {1} "
                    + "greater than configured maximum length {2} (header: {3})",
                    new Object[] { session.getSessionId(), len, maxDataLength, headerHex });
            return ProxyResult.FAIL;
        }

        byte[] data = new byte[len];
        read = readNBytes(in, data, 0, len);
        if (read != len) {
            final String dataHex = toHex(data, 0, read);
            log.log(Level.SEVERE, "(session {0}) Failed to fully read PROXY v2 data, EOF reached. Read {1}",
                    new Object[] { session.getSessionId(), dataHex });
            return ProxyResult.FAIL;
        }

        if (command == Command.LOCAL) {
            /*
             * This is a LOCAL command not a real proxy. Any proxy data existing should be ignored (just consume the
             * PROXY packet)
             */
            return ProxyResult.NOP;
        }
        
        /*
         * Data payload as seen on specs (not reporting unused remaining TLV optional data structure):
         * union proxy_addr {
         *     struct {        // for TCP/UDP over IPv4, len = 12
         *         uint32_t src_addr;
         *         uint32_t dst_addr;
         *         uint16_t src_port;
         *         uint16_t dst_port;
         *     } ipv4_addr;
         *     struct {        // for TCP/UDP over IPv6, len = 36
         *          uint8_t  src_addr[16];
         *          uint8_t  dst_addr[16];
         *          uint16_t src_port;
         *          uint16_t dst_port;
         *     } ipv6_addr;
         *     struct {        // for AF_UNIX sockets, len = 216
         *         uint8_t src_addr[108];
         *         uint8_t dst_addr[108];
         *     } unix_addr;
         * };
         */

        InetSocketAddress clientAddress;
        switch (family) {

            case UNIX:
                /*
                 * Doesn't handle unix socket proxy, fallback to unspec as requested by specifications for unsupported
                 * families.
                 */
            	log.log(Level.WARNING, "(session {0}) unsupported PROXY protocol v2 family UNIX, falling back to UNSPEC",
                        session.getSessionId());
                // SF_SWITCH_FALLTHROUGH Fallthrough

            case UNSPEC:
                /* Family unspec, ignore address data (currently proxy data as a whole, just consume the PROXY packet) */
                return ProxyResult.NOP;

            case INET: {
                byte[] raw = new byte[IPV4_LEN];
                System.arraycopy(data, 0, raw, 0, IPV4_LEN);
                InetAddress ip;
                try {
                    ip = InetAddress.getByAddress(raw);
                } catch (UnknownHostException ex) {
                    final String rawHex = toHex(raw, ':');
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v2 source IPv4 {1}", new Object[] { session.getSessionId(), rawHex });
                    return ProxyResult.FAIL;
                }

                /* We are skipping original destination address data here */
                
                /* Port as unsigned short: 2 byte */
                int port = (data[IPV4_LEN * 2] & 0xFF) << Byte.SIZE | (data[IPV4_LEN * 2 + 1] & 0xFF);

                /* We are skipping original destination port data here */
                
                clientAddress = new InetSocketAddress(ip, port);
                break;
            }

            case INET6: {
                byte[] raw = new byte[IPV6_LEN];
                System.arraycopy(data, 0, raw, 0, IPV6_LEN);
                InetAddress ip;
                try {
                    ip = InetAddress.getByAddress(raw);
                } catch (UnknownHostException ex) {
                    final String rawHex = toHex(raw, ':');
                    log.log(Level.SEVERE, "(session {0}) wrong PROXY protocol v2 source IPv6 {1}", new Object[] { session.getSessionId(), rawHex });
                    return ProxyResult.FAIL;
                }

                /* We are skipping original destination address data here */
                
                /* Port as unsigned short: 2 byte */
                int port = (data[IPV6_LEN] & 0xFF) << Byte.SIZE | (data[IPV6_LEN + 1] & 0xFF);

                /* We are skipping original destination port data here */
                
                clientAddress = new InetSocketAddress(ip, port);
                break;
            }

            default:
                log.log(Level.SEVERE, "(session {0}) Unknown PROXY protocol v2 address family {1}", new Object[] { session.getSessionId(), family });
                return ProxyResult.FAIL;
        }

        log.log(Level.FINE, "(session {0}) Accepted PROXY connection: command {1} family {2} transport {3} client {4} original {5}",
                new Object[] { session.getSessionId(), command, family, transport, clientAddress.getHostString(),
                session.getRealRemoteAddress().getHostString() });

        return new ProxyResult(clientAddress);
    }

    private static int readNBytes(InputStream is, byte[] data, int offset, int len) throws IOException {
        Preconditions.checkArgument(len >= 0);
        Preconditions.checkArgument(offset >= 0);
        Preconditions.checkArgument(offset + len <= data.length);

        final int start = offset;
        int read;
        while (len > 0 && (read = is.read(data, offset, len)) > 0) {
            offset += read;
            len -= read;
        }

        return offset - start;
    }
}
