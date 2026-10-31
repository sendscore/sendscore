package ai.sendscore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DownloadTest {
  private static final Path FIXTURES = Path.of("../../conformance/release").toAbsolutePath().normalize();
  private static HttpServer server;
  private static String base;

  @BeforeAll
  static void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", exchange -> {
      Path path = FIXTURES.resolve(exchange.getRequestURI().getPath().substring(1));
      if (Files.isRegularFile(path)) {
        byte[] body = Files.readAllBytes(path);
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
      } else {
        exchange.sendResponseHeaders(404, -1);
      }
      exchange.close();
    });
    server.start();
    base = "http://127.0.0.1:" + server.getAddress().getPort();
  }

  @AfterAll
  static void stop() {
    server.stop(0);
  }

  @Test
  void installsTheBinaryAndNothingElse(@TempDir Path tmp) throws IOException {
    String[][] targets = {{"linux", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}};
    for (int i = 0; i < targets.length; i++) {
      Path cache = tmp.resolve("cache" + i);
      Path path = Binary.download("0.0.0-test", base + "/good", cache, targets[i]);
      assertTrue(new String(Files.readAllBytes(path), StandardCharsets.UTF_8).contains("fake sendscore"));
      assertTrue(Files.isExecutable(path));
      try (Stream<Path> files = Files.list(cache)) {
        assertEquals(List.of(path.getFileName().toString()), files.map(p -> p.getFileName().toString()).collect(Collectors.toList()));
      }
      assertFalse(Files.exists(tmp.resolve("evil")));
    }
  }

  @Test
  void refusesAMismatch(@TempDir Path tmp) {
    Path cache = tmp.resolve("cache");
    assertThrows(SendScoreException.class, () -> Binary.download("0.0.0-test", base + "/tampered", cache, new String[] {"linux", "amd64"}));
    assertFalse(Files.exists(cache));
  }

  @Test
  void failsOnAMissingRelease(@TempDir Path tmp) {
    assertThrows(SendScoreException.class, () -> Binary.download("0.0.0-test", base + "/nothing", tmp.resolve("cache"), new String[] {"linux", "amd64"}));
  }
}
