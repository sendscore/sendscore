package ai.sendscore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

class ConformanceTest {
  private static final Path ROOT = Path.of("../../conformance").toAbsolutePath().normalize();

  private static List<String> list(JsonNode c, String key) {
    List<String> out = new ArrayList<>();
    c.path(key).forEach(n -> out.add(n.asText()));
    return out;
  }

  private static CheckOptions options(JsonNode c) {
    JsonNode given = c.path("options");
    CheckOptions o = new CheckOptions().offline(true);
    if (given.has("ip")) {
      o.ip(given.get("ip").asText());
    }
    if (given.has("mail_from")) {
      o.mailFrom(given.get("mail_from").asText());
    }
    if (given.has("helo")) {
      o.helo(given.get("helo").asText());
    }
    if (given.has("tls")) {
      o.tls(given.get("tls").asBoolean());
    }
    if (given.has("previous")) {
      o.previous(ROOT.resolve(given.get("previous").asText()));
    }
    return o;
  }

  private static Verdict check(JsonNode c) throws IOException {
    Path path = ROOT.resolve(c.get("message").asText());
    if (c.get("via").asText().equals("stdin")) {
      return SendScore.check(Files.readAllBytes(path), options(c));
    }
    return SendScore.check(path, options(c));
  }

  private static void changes(JsonNode c, List<Verdict.Change> got) {
    assertEquals(list(c, "changes"), got.stream().map(Verdict.Change::field).collect(Collectors.toList()));
    assertEquals(
        list(c, "worsened"),
        got.stream().map(Verdict.Change::worsened).filter(w -> w != null).collect(Collectors.toList()));
  }

  private static void run(JsonNode c) throws IOException {
    boolean isDiff = c.get("command").asText().equals("diff");
    int exit = c.get("exit").asInt();
    if (exit > 2) {
      SendScoreException e = assertThrows(SendScoreException.class, () -> {
        if (isDiff) {
          SendScore.diff(ROOT.resolve(c.get("before").asText()), ROOT.resolve(c.get("after").asText()));
        } else {
          check(c);
        }
      });
      assertEquals(exit, e.exitCode());
      return;
    }
    if (isDiff) {
      changes(c, SendScore.diff(ROOT.resolve(c.get("before").asText()), ROOT.resolve(c.get("after").asText())).changes());
      return;
    }
    Verdict got = check(c);
    assertEquals(c.get("verdict").asText(), got.verdict());
    assertEquals(c.get("ready_to_send").asBoolean(), got.readyToSend());
    Map<String, String> want = new TreeMap<>();
    c.get("checks").fields().forEachRemaining(e -> want.put(e.getKey(), e.getValue().asText()));
    Map<String, String> have = new TreeMap<>();
    got.checks().forEach(x -> have.put(x.id(), x.status()));
    assertEquals(want, have);
    changes(c, got.changes() == null ? List.of() : got.changes());
  }

  @TestFactory
  Stream<DynamicTest> cases() throws IOException {
    JsonNode file = new ObjectMapper().readTree(ROOT.resolve("cases.json").toFile());
    return StreamSupport.stream(file.get("cases").spliterator(), false)
        .map(c -> DynamicTest.dynamicTest(c.get("name").asText(), () -> run(c)));
  }
}
