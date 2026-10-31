# SendScore for Java

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict. It needs Java 17.

Not published yet.

```xml
<dependency>
  <groupId>ai.sendscore</groupId>
  <artifactId>sendscore</artifactId>
  <version>0.2.0</version>
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

## The binary

The package looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no install script.
