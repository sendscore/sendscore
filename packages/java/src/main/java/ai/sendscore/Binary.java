package ai.sendscore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
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
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Finds the CLI, and downloads a release when none is installed. */
public final class Binary {
  /** The CLI release this package downloads when none is installed. */
  public static final String ENGINE_VERSION = "0.2.0";

  private static final String RELEASES = "https://github.com/sendscore/sendscore/releases/download";

  private Binary() {}

  /** Finds the CLI: SENDSCORE_BIN, then PATH, then the cache, then a download. */
  public static String find() {
    String fromEnv = System.getenv("SENDSCORE_BIN");
    if (fromEnv != null && !fromEnv.isEmpty()) {
      return fromEnv;
    }
    String os = platform()[0];
    String exe = exe(os);
    String path = System.getenv("PATH");
    if (path != null) {
      for (String dir : path.split(File.pathSeparator)) {
        if (!dir.isEmpty() && Files.isExecutable(Path.of(dir, exe)) && Files.isRegularFile(Path.of(dir, exe))) {
          return Path.of(dir, exe).toString();
        }
      }
    }
    Path dir = cacheRoot(os).resolve("sendscore").resolve(ENGINE_VERSION);
    if (Files.isExecutable(dir.resolve(exe))) {
      return dir.resolve(exe).toString();
    }
    return download(ENGINE_VERSION, RELEASES + "/v" + ENGINE_VERSION, dir, platform()).toString();
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
        value = System.getenv("LOCALAPPDATA");
        return value != null ? Path.of(value) : home.resolve("AppData").resolve("Local");
      default:
        value = System.getenv("XDG_CACHE_HOME");
        return value != null ? Path.of(value) : home.resolve(".cache");
    }
  }

  private static byte[] fetch(HttpClient client, String url) {
    try {
      HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(120)).build();
      HttpResponse<byte[]> res = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
      if (res.statusCode() != 200) {
        throw new SendScoreException("download of " + url + " answered " + res.statusCode(), 0);
      }
      return res.body();
    } catch (IOException e) {
      throw new SendScoreException("download of " + url + " failed: " + e.getMessage(), 0);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SendScoreException("download of " + url + " was interrupted", 0);
    }
  }

  private static String expectedHash(String checksums, String name) {
    for (String line : checksums.split("\n")) {
      String[] parts = line.trim().split("\\s+");
      if (parts.length == 2 && parts[1].equals(name)) {
        return parts[0].toLowerCase(Locale.ROOT);
      }
    }
    throw new SendScoreException("checksums.txt does not list " + name, 0);
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
   * Downloads a release into dir, and returns the binary's path. The archive is checked against
   * checksums.txt before anything is extracted, so a binary that does not match never reaches
   * the disk.
   */
  static Path download(String version, String base, Path dir, String[] target) {
    String os = target[0];
    String exe = exe(os);
    String ext = os.equals("windows") ? "zip" : "tar.gz";
    String name = "sendscore_" + version + "_" + os + "_" + target[1] + "." + ext;
    HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
    String checksums = new String(fetch(client, base + "/checksums.txt"), StandardCharsets.UTF_8);
    byte[] archive = fetch(client, base + "/" + name);
    String actual;
    try {
      actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(archive));
    } catch (NoSuchAlgorithmException e) {
      throw new SendScoreException("SHA-256 is not available", 0);
    }
    if (!actual.equals(expectedHash(checksums, name))) {
      throw new SendScoreException(name + " does not match checksums.txt", 0);
    }
    try {
      byte[] binary = extract(archive, os, exe);
      if (binary == null) {
        throw new SendScoreException(name + " has no " + exe, 0);
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
