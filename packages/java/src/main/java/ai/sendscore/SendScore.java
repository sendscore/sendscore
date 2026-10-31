package ai.sendscore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Checks newsletter emails with the SendScore CLI. A message that fails checks is still a report;
 * SendScoreException means no report could be made.
 */
public final class SendScore {
  private static final ObjectMapper JSON =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private SendScore() {}

  /** Checks a saved message. */
  public static Verdict check(Path message, CheckOptions options) {
    return verdict(run(args(options, pathArg(message)), null, options.timeout()));
  }

  /** Checks a saved message. */
  public static Verdict check(Path message) {
    return check(message, new CheckOptions());
  }

  /** Checks a message given as its bytes. */
  public static Verdict check(byte[] message, CheckOptions options) {
    return verdict(run(args(options, "-"), message, options.timeout()));
  }

  /** Checks a message given as its bytes. */
  public static Verdict check(byte[] message) {
    return check(message, new CheckOptions());
  }

  /** Compares two saved messages. */
  public static Verdict.Diff diff(Path before, Path after) {
    return diff(before, after, null);
  }

  /** Compares two saved messages, killing the CLI after timeout unless it is null. */
  public static Verdict.Diff diff(Path before, Path after, Duration timeout) {
    List<String> args = List.of("diff", "--json", "--", pathArg(before), pathArg(after));
    JsonNode tree = parse(run(args, null, timeout), Set.of(0, 1));
    if (!tree.has("changes")) {
      throw new SendScoreException("sendscore printed something that is not a comparison", 0);
    }
    Verdict.Diff result = convert(tree, Verdict.Diff.class);
    return new Verdict.Diff(result.before(), result.after(), result.changes() == null ? List.of() : result.changes());
  }

  private static Verdict verdict(Result r) {
    JsonNode tree = parse(r, Set.of(0, 1, 2));
    if (!tree.path("schema").asText().startsWith("sendscore.verdict/")) {
      throw new SendScoreException("sendscore printed something that is not a verdict", 0);
    }
    return convert(tree, Verdict.class);
  }

  /** A lone "-" would mean standard input to the CLI. */
  static String pathArg(Path path) {
    String text = path.toString();
    return text.equals("-") ? "./-" : text;
  }

  private static List<String> args(CheckOptions options, String input) {
    List<String> args = new ArrayList<>(List.of("check", "--json"));
    args.addAll(options.args());
    args.addAll(List.of("--", input));
    return args;
  }

  private record Result(int code, byte[] stdout, byte[] stderr) {}

  private static final class Drain {
    private final Thread thread;
    private volatile byte[] bytes = new byte[0];

    Drain(InputStream stream) {
      thread = new Thread(() -> {
        try {
          bytes = stream.readAllBytes();
        } catch (IOException e) {
          // The stream ended with the process.
        }
      });
      thread.setDaemon(true);
      thread.start();
    }

    byte[] finish() throws InterruptedException {
      thread.join();
      return bytes;
    }
  }

  private static Result run(List<String> args, byte[] stdin, Duration timeout) {
    String binary = Binary.find();
    List<String> command = new ArrayList<>(List.of(binary));
    command.addAll(args);
    Process process = null;
    try {
      // A list of arguments runs the program directly, with no shell.
      process = new ProcessBuilder(command).start();
      Drain stdout = new Drain(process.getInputStream());
      Drain stderr = new Drain(process.getErrorStream());
      OutputStream in = process.getOutputStream();
      Thread writer = new Thread(() -> {
        try (in) {
          if (stdin != null) {
            in.write(stdin);
          }
        } catch (IOException e) {
          // The CLI stopped reading, and its exit code says why.
        }
      });
      writer.setDaemon(true);
      writer.start();
      if (timeout == null) {
        process.waitFor();
      } else if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
        throw new SendScoreException("sendscore did not finish within " + timeout, SendScoreException.KILLED);
      }
      int code = process.exitValue();
      return new Result(code < 0 || code >= 128 ? SendScoreException.KILLED : code, stdout.finish(), stderr.finish());
    } catch (IOException e) {
      throw new SendScoreException("could not run " + binary + ": " + e.getMessage(), 0);
    } catch (InterruptedException e) {
      process.destroyForcibly();
      Thread.currentThread().interrupt();
      throw new SendScoreException("interrupted while running " + binary, SendScoreException.KILLED);
    }
  }

  private static JsonNode parse(Result r, Set<Integer> verdictCodes) {
    if (!verdictCodes.contains(r.code())) {
      String text = new String(r.stderr(), StandardCharsets.UTF_8).trim();
      throw new SendScoreException(text.isEmpty() ? "sendscore exited " + r.code() : text, r.code());
    }
    try {
      JsonNode tree = JSON.readTree(r.stdout());
      if (tree == null || !tree.isObject()) {
        throw new SendScoreException("sendscore printed something that is not a report", r.code());
      }
      return tree;
    } catch (JsonProcessingException e) {
      throw new SendScoreException("sendscore printed something this package cannot read", r.code());
    } catch (IOException e) {
      throw new SendScoreException("could not read the report: " + e.getMessage(), r.code());
    }
  }

  private static <T> T convert(JsonNode tree, Class<T> type) {
    try {
      return JSON.treeToValue(tree, type);
    } catch (JsonProcessingException e) {
      throw new SendScoreException("sendscore printed something this package cannot read", 0);
    }
  }
}
