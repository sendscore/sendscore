package ai.sendscore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Finds the CLI, and downloads a release when none is installed. */
public final class Binary {
  /** The CLI release this package downloads when none is installed. */
  public static final String ENGINE_VERSION = "0.3.0";

  private static final String RELEASES = "https://github.com/sendscore/sendscore/releases/download";

  private static final int MAX_DOWNLOAD = 100 << 20;

  /** The environment to read, which tests replace because Java cannot set its own. */
  static Map<String, String> env = System.getenv();

  private Binary() {}

  /**
   * Finds the CLI: SENDSCORE_BIN, then the pinned version on PATH, then the cache, then a download.
   * A cached binary is checked against its pinned hash every time, so a file planted in the cache
   * is replaced and never run.
   */
  public static String find() {
    String fromEnv = env.get("SENDSCORE_BIN");
    if (fromEnv != null && !fromEnv.isEmpty()) {
      return fromEnv;
    }
    String found = onPath();
    return found != null ? found : installed(Hashes.PINS);
  }

  /** The pinned version on PATH, or null. */
  static String onPath() {
    String exe = exe(windows() ? "windows" : "unix");
    String path = env.get("PATH");
    if (path != null) {
      for (String dir : path.split(File.pathSeparator)) {
        if (dir.isEmpty() || !Path.of(dir).isAbsolute()) {
          continue;
        }
        Path candidate = Path.of(dir, exe);
        if (Files.isRegularFile(candidate) && Files.isExecutable(candidate) && rightVersion(candidate.toString())) {
          return candidate.toString();
        }
      }
    }
    return null;
  }

  /** The cached binary, or a download, as the pins allow. */
  static String installed(Map<String, String[]> pins) {
    String[] target = platform();
    String[] pin = pinFor(target, pins);
    String exe = exe(target[0]);
    Path dir = cacheRoot(target[0]).resolve("sendscore").resolve(ENGINE_VERSION);
    if (matchesPin(dir.resolve(exe), pin)) {
      return dir.resolve(exe).toString();
    }
    return download(ENGINE_VERSION, RELEASES + "/v" + ENGINE_VERSION, dir, pin, target).toString();
  }

  private static boolean windows() {
    return System.getProperty("os.name").toLowerCase(Locale.ROOT).startsWith("windows");
  }

  private static boolean rightVersion(String path) {
    try {
      Process process = new ProcessBuilder(path, "--version").redirectErrorStream(true).start();
      process.getOutputStream().close();
      byte[][] out = new byte[1][];
      Thread reader = new Thread(() -> {
        try (InputStream in = process.getInputStream()) {
          out[0] = in.readNBytes(4096);
        } catch (IOException e) {
          out[0] = new byte[0];
        }
      });
      reader.setDaemon(true);
      reader.start();
      if (!process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
        process.destroyForcibly();
        return false;
      }
      reader.join(1000);
      String[] words = new String(out[0] == null ? new byte[0] : out[0], StandardCharsets.UTF_8).trim().split("\\s+");
      return process.exitValue() == 0 && words[words.length - 1].replaceFirst("^v", "").equals(ENGINE_VERSION);
    } catch (IOException e) {
      return false;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  /** The archive and binary hashes of a platform. With none, nothing is trusted. */
  static String[] pinFor(String[] target, Map<String, String[]> pins) {
    String key = target[0] + "_" + target[1];
    String[] pin = pins.get(key);
    if (pin == null) {
      throw new SendScoreException(
          "this package has no pinned hash for " + key
              + ", so it will not download a CLI. Install the matching sendscore on PATH, or set SENDSCORE_BIN.",
          0);
    }
    return pin;
  }

  /** Whether a file exists and is exactly the pinned binary. */
  static boolean matchesPin(Path path, String[] pin) {
    try {
      return Files.isRegularFile(path) && sha256(Files.readAllBytes(path)).equals(pin[1]);
    } catch (IOException e) {
      return false;
    }
  }

  private static String sha256(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new SendScoreException("SHA-256 is not available", 0);
    }
  }

  private static String exe(String os) {
    return os.equals("windows") ? "sendscore.exe" : "sendscore";
  }

  static String[] platform() {
    String osName = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    String arch = System.getProperty("os.arch").toLowerCase(Locale.ROOT);
    String os = osName.contains("win") && !osName.contains("darwin")
        ? "windows"
        : osName.contains("mac") ? "darwin" : osName.contains("linux") ? "linux" : null;
    String cpu = switch (arch) {
      case "amd64", "x86_64" -> "amd64";
      case "aarch64", "arm64" -> "arm64";
      default -> null;
    };
    if (os == null || cpu == null) {
      throw new SendScoreException("no SendScore build for " + osName + " on " + arch, 0);
    }
    return new String[] {os, cpu};
  }

  private static Path cacheRoot(String os) {
    Path home = Path.of(System.getProperty("user.home"));
    String value;
    switch (os) {
      case "darwin":
        return home.resolve("Library").resolve("Caches");
      case "windows":
        value = env.get("LOCALAPPDATA");
        return value != null && !value.isEmpty() ? Path.of(value) : home.resolve("AppData").resolve("Local");
      default:
        value = env.get("XDG_CACHE_HOME");
        return value != null && Path.of(value).isAbsolute() ? Path.of(value) : home.resolve(".cache");
    }
  }

  private static byte[] fetch(HttpClient client, String url) {
    try {
      HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(120)).build();
      HttpResponse<InputStream> res = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
      try (InputStream body = res.body()) {
        if (res.statusCode() != 200) {
          throw new SendScoreException("download of " + url + " answered " + res.statusCode(), 0);
        }
        byte[] bytes = body.readNBytes(MAX_DOWNLOAD + 1);
        if (bytes.length > MAX_DOWNLOAD) {
          throw new SendScoreException("download of " + url + " is too large", 0);
        }
        return bytes;
      }
    } catch (IOException e) {
      throw new SendScoreException("download of " + url + " failed: " + e.getMessage(), 0);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SendScoreException("download of " + url + " was interrupted", 0);
    }
  }

  // One file, by its exact name, so no path in the archive is ever used.
  private static byte[] fromTar(byte[] tar, String name) {
    for (int at = 0; at + 512 <= tar.length; ) {
      int end = at;
      while (end < at + 100 && tar[end] != 0) {
        end++;
      }
      if (end == at) {
        return null;
      }
      String entry = new String(tar, at, end - at, StandardCharsets.UTF_8);
      String octal = new String(tar, at + 124, 12, StandardCharsets.US_ASCII).replace("\0", "").trim();
      int size = octal.isEmpty() ? 0 : Integer.parseInt(octal, 8);
      byte type = tar[at + 156];
      at += 512;
      if (entry.equals(name) && (type == '0' || type == 0)) {
        byte[] out = new byte[size];
        System.arraycopy(tar, at, out, 0, size);
        return out;
      }
      at += (size + 511) / 512 * 512;
    }
    return null;
  }

  private static byte[] extract(byte[] archive, String os, String name) throws IOException {
    if (os.equals("windows")) {
      try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
        for (ZipEntry e = zip.getNextEntry(); e != null; e = zip.getNextEntry()) {
          if (e.getName().equals(name)) {
            return zip.readAllBytes();
          }
        }
      }
      return null;
    }
    ByteArrayOutputStream tar = new ByteArrayOutputStream();
    try (GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(archive))) {
      gz.transferTo(tar);
    }
    return fromTar(tar.toByteArray(), name);
  }

  /**
   * Downloads a release into dir, and returns the binary's path. The archive must match its pin
   * before anything is extracted, and the binary must match its pin before it reaches the disk.
   */
  static Path download(String version, String base, Path dir, String[] pin, String[] target) {
    String os = target[0];
    String exe = exe(os);
    String ext = os.equals("windows") ? "zip" : "tar.gz";
    String name = "sendscore_" + version + "_" + os + "_" + target[1] + "." + ext;
    HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
    byte[] archive = fetch(client, base + "/" + name);
    if (!sha256(archive).equals(pin[0])) {
      throw new SendScoreException(name + " does not match its pinned hash", 0);
    }
    try {
      byte[] binary = extract(archive, os, exe);
      if (binary == null) {
        throw new SendScoreException(name + " has no " + exe, 0);
      }
      if (!sha256(binary).equals(pin[1])) {
        throw new SendScoreException("the binary in " + name + " does not match its pinned hash", 0);
      }
      Files.createDirectories(dir);
      Path temp = Files.createTempFile(dir, ".download-", null);
      try {
        Files.write(temp, binary);
        temp.toFile().setExecutable(true, false);
        Path path = dir.resolve(exe);
        try {
          Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
          Files.move(temp, path, StandardCopyOption.REPLACE_EXISTING);
        }
        return path;
      } finally {
        Files.deleteIfExists(temp);
      }
    } catch (IOException e) {
      throw new SendScoreException("could not install " + name + ": " + e.getMessage(), 0);
    }
  }
}
