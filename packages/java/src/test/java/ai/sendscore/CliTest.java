package ai.sendscore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Isolated;

@Isolated
class CliTest {
  private static final Path REPO = Path.of("../..").toAbsolutePath().normalize();
  private static final Path SAMPLE = REPO.resolve("conformance/messages/clean.eml");
  private static final boolean WINDOWS = System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
  private static final String EXE = WINDOWS ? "sendscore.exe" : "sendscore";

  @TempDir static Path tmp;
  private static Path built;

  @BeforeAll
  static void build() throws IOException, InterruptedException {
    built = tmp.resolve("built").resolve(EXE);
    Process go = new ProcessBuilder("go", "build", "-o", built.toString(), "./conformance/fakecli")
        .directory(REPO.toFile()).inheritIO().start();
    assertEquals(0, go.waitFor());
  }

  @AfterEach
  void restore() {
    Binary.env = System.getenv();
  }

  private static Path fake(String mode) throws IOException {
    Path dir = tmp.resolve(mode);
    Files.createDirectories(dir);
    Path path = dir.resolve(EXE);
    Files.copy(built, path, StandardCopyOption.REPLACE_EXISTING);
    path.toFile().setExecutable(true, false);
    return path;
  }

  private static void using(Path path) {
    Binary.env = Map.of("SENDSCORE_BIN", path.toString());
  }

  private static void onlyPath(String path) {
    Map<String, String> env = new HashMap<>();
    env.put("PATH", path);
    env.put("XDG_CACHE_HOME", tmp.resolve("cache").toString());
    env.put("LOCALAPPDATA", tmp.resolve("cache").toString());
    Binary.env = env;
  }

  @Test
  void aTimeoutKillsTheCli() throws IOException {
    using(fake("hang"));
    Duration t = Duration.ofMillis(200);
    assertEquals(SendScoreException.KILLED, assertThrows(SendScoreException.class, () -> SendScore.check(SAMPLE, new CheckOptions().timeout(t))).exitCode());
    assertEquals(SendScoreException.KILLED, assertThrows(SendScoreException.class, () -> SendScore.diff(SAMPLE, SAMPLE, t)).exitCode());
  }

  @Test
  void aKilledCliHasOneExitCode() throws IOException {
    assumeFalse(WINDOWS);
    using(fake("killed"));
    assertEquals(SendScoreException.KILLED, assertThrows(SendScoreException.class, () -> SendScore.check(SAMPLE)).exitCode());
  }

  @Test
  void outputThatIsNotAVerdictIsRefused() throws IOException {
    using(fake("planted"));
    assertThrows(SendScoreException.class, () -> SendScore.check(SAMPLE));
    assertThrows(SendScoreException.class, () -> SendScore.diff(SAMPLE, SAMPLE));
  }

  @Test
  void unknownFieldsAndStderrAreTolerated() throws IOException {
    using(fake("noisy"));
    Verdict got = SendScore.check(SAMPLE);
    assertEquals("pass", got.verdict());
    assertEquals("brand_new", got.checks().get(0).status());
  }

  @Test
  void aWrongVersionOnPathIsNotRun() throws IOException {
    onlyPath(fake("version-9.9.9").getParent().toString());
    assertNull(Binary.onPath());
  }

  @Test
  void withNoPinsNothingIsInstalled() {
    SendScoreException e = assertThrows(SendScoreException.class, () -> Binary.installed(Map.of()));
    assertTrue(e.getMessage().contains("no pinned hash"));
  }

  @Test
  void thePinnedVersionOnPathIsUsed() throws IOException {
    Path path = fake("version-" + Binary.ENGINE_VERSION);
    onlyPath(path.getParent().toString());
    assertEquals(path.toString(), Binary.find());
  }

  @Test
  void relativePathEntriesAreSkipped() throws IOException {
    String name = "version-" + Binary.ENGINE_VERSION;
    Path copy = Path.of(name, EXE);
    Files.createDirectories(copy.getParent());
    Files.copy(fake(name), copy, StandardCopyOption.REPLACE_EXISTING);
    copy.toFile().setExecutable(true, false);
    try {
      onlyPath(File.pathSeparator + name);
      assertNull(Binary.onPath());
    } finally {
      Files.deleteIfExists(copy);
      Files.deleteIfExists(copy.getParent());
    }
  }

  @Test
  void pathsThatLookLikeFlagsAreFiles() throws IOException {
    for (String name : new String[] {"-", "-dash.eml"}) {
      Path file = Path.of(name);
      Files.copy(SAMPLE, file, StandardCopyOption.REPLACE_EXISTING);
      try {
        assertFalse(SendScore.check(file, new CheckOptions().offline(true)).message().subject().isEmpty());
      } finally {
        Files.deleteIfExists(file);
      }
    }
  }
}
