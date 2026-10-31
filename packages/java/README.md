# SendScore for Java

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict. It needs Java 17.

Not published yet.

```xml
<dependency>
  <groupId>ai.sendscore</groupId>
  <artifactId>sendscore</artifactId>
  <version>0.3.0</version>
</dependency>
```

```java
import ai.sendscore.CheckOptions;
import ai.sendscore.SendScore;
import ai.sendscore.Verdict;
import java.nio.file.Path;

Verdict verdict = SendScore.check(Path.of("issue.eml"));
if (!verdict.readyToSend()) {
  verdict.topFixes().forEach(fix -> System.out.println(fix.who() + " " + fix.fix()));
}

SendScore.check(rawBytes, new CheckOptions().offline(true));
SendScore.diff(Path.of("before.eml"), Path.of("after.eml"));
```

A message that fails its checks is still a report, so `check` returns it. `SendScoreException` is thrown only when no report could be made, and its `exitCode()` is the CLI's. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

Use `CheckOptions.timeout` or the `diff` overload to kill the CLI when it runs out. A killed CLI throws `SendScoreException` with `exitCode()` equal to `SendScoreException.KILLED`, which is -1. Interrupting the calling thread kills it too.

## The binary

The package uses `SENDSCORE_BIN`, then the CLI on `PATH` if its version matches, then your user cache. If none has it, the first call downloads the pinned release from GitHub. The package carries the SHA-256 of each release file and of the binary inside it, and checks them before it runs anything, including a cached binary. `SENDSCORE_BIN` is your own choice, so its version is not checked. There is no install script.
