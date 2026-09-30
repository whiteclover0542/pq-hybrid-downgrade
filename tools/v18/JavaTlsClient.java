import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** Minimal JSSE default-configuration probe for the loopback v1.8 survey. */
public final class JavaTlsClient {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: JavaTlsClient HOST PORT");
        }
        TrustManager[] trustAll = {new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            public void checkClientTrusted(X509Certificate[] chain, String authType) { }
            public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        }};
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new SecureRandom());
        try (Socket socket = context.getSocketFactory().createSocket(args[0], Integer.parseInt(args[1]))) {
            SSLSocket tls = (SSLSocket) socket;
            tls.setEnabledProtocols(new String[] {"TLSv1.3"});
            tls.startHandshake();
            System.out.println("TLS protocol: " + tls.getSession().getProtocol());
        }
    }
}
