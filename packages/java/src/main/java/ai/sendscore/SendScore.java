package ai.sendscore;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

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
    return parse(run(args(options, message.toString()), null), Set.of(0, 1, 2), Verdict.class);
  }

  /** Checks a saved message. */
  public static Verdict check(Path message) {
    return check(message, new CheckOptions());
  }

  /** Checks a message given as its bytes. */
  public static Verdict check(byte[] message, CheckOptions options) {
    return parse(run(args(options, "-"), message), Set.of(0, 1, 2), Verdict.class);
  }

  /** Checks a message given as its bytes. */
  public static Verdict check(byte[] message) {
    return check(message, new CheckOptions());
  }

  /** Compares two saved messages. */
  public static Verdict.Diff diff(Path before, Path after) {
    List<String> args = List.of("diff", "--json", "--", before.toString(), after.toString());
    Verdict.Diff result = parse(run(args, null), Set.of(0, 1), Verdict.Diff.class);
    return new Verdict.Diff(result.before(), result.after(), result.changes() == null ? List.of() : result.changes());
  }

  private static List<String> args(CheckOptions options, String input) {
    List<String> args = new ArrayList<>(List.of("check", "--json"));
    args.addAll(options.args());
    args.addAll(List.of("--", input));
    return args;
  }

  private record Result(int code, byte[] stdout, byte[] stderr) {}

  private static Result run(List<String> args, byte[] stdin) {
    String binary = Binary.find();
    List<String> command = new ArrayList<>(List.of(binary));
    command.addAll(args);
    try {
      // A list of arguments runs the program directly, with no shell.
      Process process = new ProcessBuilder(command).start();
      CompletableFuture<byte[]> stdout = drain(process.getInputStream());
      CompletableFuture<byte[]> stderr = drain(process.getErrorStream());
      try (OutputStream in = process.getOutputStream()) {
        if (stdin != null) {
          in.write(stdin);
        }
      } catch (IOException e) {
        // The CLI stopped reading, and its exit code says why.
      }
      return new Result(process.waitFor(), stdout.join(), stderr.join());
    } catch (IOException e) {
      throw new SendScoreException("could not run " + binary + ": " + e.getMessage(), 0);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new SendScoreException("interrupted while running " + binary, 0);
    }
  }

  private static CompletableFuture<byte[]> drain(java.io.InputStream stream) {
    return CompletableFuture.supplyAsync(() -> {
      try {
        return stream.readAllBytes();
      } catch (IOException e) {
        return new byte[0];
      }
    });
  }

  private static <T> T parse(Result r, Set<Integer> verdictCodes, Class<T> type) {
    if (!verdictCodes.contains(r.code())) {
      String text = new String(r.stderr(), StandardCharsets.UTF_8).trim();
      throw new SendScoreException(text.isEmpty() ? "sendscore exited " + r.code() : text, r.code());
    }
    try {
      return JSON.readValue(r.stdout(), type);
    } catch (JsonProcessingException e) {
      throw new SendScoreException("sendscore printed something this package cannot read", r.code());
    } catch (IOException e) {
      throw new SendScoreException("could not read the report: " + e.getMessage(), r.code());
    }
  }
}
