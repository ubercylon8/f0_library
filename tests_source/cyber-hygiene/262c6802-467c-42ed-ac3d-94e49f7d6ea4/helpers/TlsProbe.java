import java.net.Socket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLHandshakeException;

public final class TlsProbe {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("F0_ERROR expected port and server name");
            System.exit(3);
        }
        try {
            int port = Integer.parseInt(args[0]);
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            Socket plain = new Socket("127.0.0.1", port);
            plain.setSoTimeout(10000);
            SSLSocket socket = (SSLSocket) factory.createSocket(plain, args[1], port, true);
            socket.setUseClientMode(true);
            socket.setSoTimeout(10000);
            socket.startHandshake();
            System.out.println("F0_ACCEPTED " + socket.getSession().getProtocol());
            socket.close();
        } catch (SSLHandshakeException error) {
            String chain = causalChain(error).toLowerCase();
            if (chain.contains("cert") || chain.contains("pkix") || chain.contains("trust") || chain.contains("revok")) {
                System.out.println("F0_REJECTED " + causalChain(error));
                System.exit(2);
            }
            System.out.println("F0_ERROR " + causalChain(error));
            System.exit(3);
        } catch (Exception error) {
            System.out.println("F0_ERROR " + causalChain(error));
            System.exit(3);
        }
    }

    private static String causalChain(Throwable error) {
        StringBuilder result = new StringBuilder();
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (result.length() > 0) {
                result.append(" <- ");
            }
            result.append(current.getClass().getSimpleName());
            if (current.getMessage() != null) {
                result.append(": ").append(current.getMessage());
            }
        }
        return result.toString().replace('\n', ' ').replace('\r', ' ');
    }
}
