import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.Certificate;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public final class Server {

	private Map<String, byte[]> resourceMap;
	private Map<String, String> redirectMap;
	private ServerSocket socket;
	private DataOutputStream toClientStream;
	private BufferedReader fromClientStream;
	private boolean connection;

	public void loadResources() throws IOException {
		resourceMap = ResourceMap.loadFiles();
		redirectMap = ResourceMap.loadRedirects();
	}

	/**
	 * Creates a socket + binds to the desired server-side port #.
	 *
	 * @throws {@link IOException} if the port is already in use.
	 */
	public void bindHTTPS(int sslServerPort) throws IOException {
		final char[] JKS_PASSWORD = "password".toCharArray();
		final char[] KEY_PASSWORD = "password".toCharArray();
		try {
		/* Get the JKS contents */
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			final InputStream is = new FileInputStream("server.jks");
			keyStore.load(is, JKS_PASSWORD);
			final KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
//			System.out.println(kmf.getProvider());
			kmf.init(keyStore, KEY_PASSWORD);
//			final TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
//			tmf.init(keyStore);
// Create a trust manager that does not validate certificate chains
			TrustManager[] trustAllCerts = new TrustManager[] {
					new X509TrustManager() {
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return new X509Certificate[0];
						}
						public void checkClientTrusted(
								java.security.cert.X509Certificate[] certs, String authType) {
						}
						public void checkServerTrusted(
								java.security.cert.X509Certificate[] certs, String authType) {
						}
					}
			};
			SSLContext context = SSLContext.getInstance("SSL");
//			context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
			context.init(kmf.getKeyManagers(), trustAllCerts, new SecureRandom());
			SSLServerSocketFactory ssf = context.getServerSocketFactory();

			System.out.println("Attempting to bind on " + sslServerPort);
			socket = ssf.createServerSocket(sslServerPort);

			System.out.println("Server bound and listening to port " + sslServerPort);
		}
		catch(Exception ex){
			System.out.println(ex);
		}
	}

	public void bindHTTP(int serverPort) throws IOException {
		System.out.println("Attempting to bind on " + serverPort);
		socket = new ServerSocket(serverPort);
		System.out.println("Server bound and listening to port " + serverPort);
	}

	/**
	 * Waits for a client to connect, and then sets up stream objects for communication
 	 * in both directions.
	 *
	 * @return The newly-created client {@link Socket} if the connection is successfully
	 *     established, or {@code null} otherwise.
	 * @throws {@link IOException} if the server fails to accept the connection.
	 */
	public Socket acceptFromClient() throws IOException {

		Socket clientSocket;
		try {
			clientSocket = socket.accept();


		} catch (SecurityException e) {
			System.out.println("The security manager intervened; your config is very wrong. " + e);
			return null;
		} catch (IllegalArgumentException e) {
			System.out.println("Probably an invalid port number. " + e);
			return null;
		} catch (IOException e) {
			System.out.println("IOException in socket.accept()");
			return null;
		}

		try {
			toClientStream = new DataOutputStream(clientSocket.getOutputStream());
			fromClientStream = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
		} catch (IOException e) {
			System.out.println("exception creating the stream objects.");
		}
		return clientSocket;
	}

	public void handleRequest() throws IOException {
		List<String> rawRequest = new ArrayList<String>();
		String inputLine;
		do {
			inputLine = fromClientStream.readLine();
//			while (inputLine == null) {
//				System.out.println("inputLine was null!\n");
//				inputLine = fromClientStream.readLine();
//			}
			rawRequest.add(inputLine);
		} while ((inputLine != null) && (inputLine.length() > 0));

		if (rawRequest == null)
			return;

		System.out.println(String.format("[%s]", rawRequest));
		HTTPRequest request = new HTTPRequest(rawRequest);
		connection = request.getConnection();
		System.out.println(request);

		// TODO(ajn): support POST along with GET/HEAD
		if (request.getType() != HTTPRequest.Command.GET && 
				request.getType() != HTTPRequest.Command.HEAD) {
			send403(request, String.format("%s not supported.", request.getType()));
			return;
		}

		// See if this is supposed to be a redirect, first.
		if (redirectMap.containsKey(request.getPath())) {
			send301(request, redirectMap.get(request.getPath()));
		} else if (!resourceMap.containsKey(request.getPath())) {
			send404(request);
		} else {
			byte[] content = resourceMap.get(request.getPath());
			send200(request, content, ResourceMap.contentTypeFromFilename(request.getPath()));	
		}

		// Close connection if client wants to close the connection

	}

	private void send301(HTTPRequest request, String newUrl) throws IOException {
		String responseBody = new StringBuilder()
				.append("<HTML><HEAD><TITLE>301 Moved</TITLE></HEAD>\r\n")
    		.append("<BODY><H1>These aren't the droids you're looking for.</H1>\r\n")
    		.append(String.format("This resource has moved <A HREF=\"%s\">here</A>.\r\n", newUrl))
    		.append("</BODY></HTML>\r\n")
				.toString();

		StringBuilder response = new StringBuilder()
				.append("HTTP/1.1 301 Moved Permanently\r\n")
				.append(String.format("Location: %s\r\n", newUrl))
				.append(String.format("Content-Type: text/html\r\n"))
				.append("Connection: close\r\n")
				.append(String.format("Content-Length: %d\r\n", responseBody.length()));
		if (request.getType() == HTTPRequest.Command.GET) {
				response.append(String.format("\r\n%s", responseBody));
		}
		toClientStream.writeBytes(response.toString());
	}

	private void send404(HTTPRequest request) throws IOException {
		String responseBody = new StringBuilder()
				.append("<HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD>\r\n")
				.append("<BODY><H1>I can't find any resource of the name \r\n")
				.append(String.format("[%s] on this server.\r\n", request.getPath()))
				.append("</BODY></HTML>\r\n")
				.toString();

		StringBuilder response = new StringBuilder()
				.append("HTTP/1.1 404 Not Found\r\n")
				.append("Content-Type: text/html\r\n")
				.append("Connection: close\r\n")
				.append(String.format("Content-Length: %d\r\n", responseBody.length()));
		if (request.getType() == HTTPRequest.Command.GET) {
				response.append(String.format("\r\n%s\r\n", responseBody));
		}
		try {
			toClientStream.writeBytes(response.toString());	
		} catch (IOException e) {
			System.out.println("Client closed the socket before we finished the whole message.");
		}
	}

	private void send403(HTTPRequest request, String errorDetail) throws IOException {
		StringBuilder response = new StringBuilder()
				.append("HTTP/1.1 403 Forbidden\r\n")
				.append("Connection: close\r\n")
				.append(String.format("Context-Length: %d\r\n", errorDetail.length()));
		if (request.getType() == HTTPRequest.Command.GET) {
				response.append(String.format("\r\n%s\r\n", errorDetail));
		}
		toClientStream.writeBytes(response.toString());	
	}

	private void send200(HTTPRequest request, byte[] content, String mimeType) throws IOException {
		StringBuilder response = new StringBuilder()
				.append("HTTP/1.1 200 OK\r\n")
				.append("Content-Type: " + mimeType + "\r\n")
				.append("Server: project1\r\n")
				.append("Connection: close\r\n")
				.append(String.format("Content-Length: %d\r\n", content.length));
		toClientStream.writeBytes(response.toString());
		if (request.getType() == HTTPRequest.Command.GET) {
				toClientStream.writeBytes("\r\n");
				ByteArrayOutputStream outByteStream = new ByteArrayOutputStream();
				outByteStream.write(content, 0, content.length);
				outByteStream.writeTo(toClientStream);
		}
	}

	public void bootHTTP(int serverPort){
		connection = true;
		try {
			this.loadResources();
			this.bindHTTP(serverPort);
			this.readStuff();
		} catch (IOException e) {
			System.out.println("Error communicating with client. aborting. Details: " + e);
		}
	}

	public void bootHTTPS(int sslServerPort){
		connection = true;
		try {
			this.loadResources();
			this.bindHTTPS(sslServerPort);
			this.readStuff();
		} catch (IOException e) {
			System.out.println("Error communicating with client. aborting. Details: " + e);
		}
	}

	public void readStuff() throws IOException {
		while(true) {
			Socket clientSocket = this.acceptFromClient();
			if (clientSocket != null && clientSocket.isConnected()) {
				try {
					this.handleRequest();
				} catch (IOException e) {
					System.out.println("IO exception handling request, continuing.");
				}
				try {
					if(!connection){
						clientSocket.close();
						System.out.println("Closing Socket");
					}

				} catch (IOException e) {
					System.out.println("it's ok; the server already closed the connection.");
				}
			}
		}
	}


	public static void main(String argv[]) {
		Map<String, String> flags = Utils.parseCmdlineFlags(argv);
		if (!flags.containsKey("--serverPort")) {
			System.out.println("usage: Server --serverPort=12345");
			System.exit(-1);
		}

		int serverPort = -1;
		int sslServerPort = -1;

		try {
			serverPort = Integer.parseInt(flags.get("--serverPort"));
		} catch (NumberFormatException e) {
			System.out.println("Invalid port number! Must be an integer.");
			System.exit(-1);
		}


		try {
			serverPort = Integer.parseInt(flags.get("--serverPort"));
			System.out.println("serverPort: " + serverPort);
			sslServerPort = Integer.parseInt(flags.get("--sslServerPort"));
			System.out.println("sslServerPort: " + sslServerPort);
		} catch (NumberFormatException e) {
			System.out.println("Invalid port number! Must be an integer.");
			System.exit(-1);
		}

		Server serverHTTP = new Server();
		ServerThread threadHTTP = new ServerThread("HTTP",serverHTTP,serverPort);
		threadHTTP.start();
////
		Server serverHTTPS = new Server();
		ServerThread threadHTTPS = new ServerThread("HTTPS",serverHTTPS,sslServerPort);
		threadHTTPS.start();

	}

}

class ServerThread implements Runnable {
	private Thread t;
	private String threadName;
	private Server server;
	private String serverType;
	private int portNumber;

	ServerThread(String name, Server server, int portNumber){
		threadName = name;
		this.server = server;
		this.serverType = name;
		this.portNumber = portNumber;
	}

	public void run() {
		if (serverType.equals("HTTP")) {
			server.bootHTTP(portNumber);
		} else {
			server.bootHTTPS(portNumber);
		}
	}

	public void start() {
		if (t == null)
		{
			t = new Thread (this, threadName);
			t.start ();
		}
	}

}

