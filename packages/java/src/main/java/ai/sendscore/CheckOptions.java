package ai.sendscore;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** What a check should do beyond reading the message. */
public final class CheckOptions {
  private boolean offline;
  private boolean links;
  private String ip;
  private String mailFrom;
  private String helo;
  private Boolean tls;
  private Path previous;
  private Duration timeout;

  /** Make no DNS lookups. Checks that need DNS are skipped. */
  public CheckOptions offline(boolean value) {
    offline = value;
    return this;
  }

  /** Fetch every link and image, never unsubscribe or confirm links. */
  public CheckOptions links(boolean value) {
    links = value;
    return this;
  }

  /** IP address of the server that delivered the message. */
  public CheckOptions ip(String value) {
    ip = value;
    return this;
  }

  /** Envelope sender. Defaults to the Return-Path. */
  public CheckOptions mailFrom(String value) {
    mailFrom = value;
    return this;
  }

  /** HELO name the delivering server gave. */
  public CheckOptions helo(String value) {
    helo = value;
    return this;
  }

  /** Whether delivery used TLS. */
  public CheckOptions tls(boolean value) {
    tls = value;
    return this;
  }

  /** The publication's previous issue, to list what changed. */
  public CheckOptions previous(Path value) {
    previous = value;
    return this;
  }

  /** Kill the CLI and throw after this long. No limit by default. */
  public CheckOptions timeout(Duration value) {
    timeout = value;
    return this;
  }

  Duration timeout() {
    return timeout;
  }

  List<String> args() {
    List<String> out = new ArrayList<>();
    if (offline) {
      out.add("--offline");
    }
    if (links) {
      out.add("--links");
    }
    if (ip != null) {
      out.addAll(List.of("--ip", ip));
    }
    if (mailFrom != null) {
      out.addAll(List.of("--mail-from", mailFrom));
    }
    if (helo != null) {
      out.addAll(List.of("--helo", helo));
    }
    if (tls != null) {
      out.addAll(List.of("--tls", tls ? "yes" : "no"));
    }
    if (previous != null) {
      out.addAll(List.of("--previous", SendScore.pathArg(previous)));
    }
    return out;
  }
}
