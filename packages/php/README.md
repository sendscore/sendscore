# SendScore for PHP

A typed wrapper around the [SendScore](https://github.com/sendscore/sendscore) CLI, which checks a newsletter email before it goes out. Every language package runs the same binary, so they all return the same verdict.

Not published yet.

```sh
composer require sendscore/sendscore
```

```php
use SendScore\SendScore;

$verdict = SendScore::check('issue.eml');
if (!$verdict['ready_to_send']) {
    foreach ($verdict['top_fixes'] as $fix) {
        echo $fix['who'], ' ', $fix['fix'], "\n";
    }
}

SendScore::check($rawBytes, ['stdin' => true, 'offline' => true]);
SendScore::diff('before.eml', 'after.eml');
```

A message that fails its checks is still a report, so `check` returns it. `SendScoreException` is thrown only when no report could be made, and its `getCode()` is the CLI's exit code. Receipt at SendScore does not prove inbox placement at Gmail or any other provider.

## The binary

The package looks for the CLI in `SENDSCORE_BIN`, then on `PATH`, then in your user cache. If none has it, the first call downloads the pinned release from GitHub, and checks it against the release's `checksums.txt` before it is ever run. There is no install script.
