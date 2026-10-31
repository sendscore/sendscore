<?php

declare(strict_types=1);

namespace SendScore;

/**
 * Checks newsletter emails with the SendScore CLI. Reports are the
 * sendscore.verdict/v1 JSON as associative arrays, and new keys may appear.
 *
 * @phpstan-type Check array{id: string, category: string, status: string, title: string, detail?: string, evidence?: array<string, mixed>, fix?: array{who: string, text: string}, docs?: string, reason?: string}
 * @phpstan-type Change array{field: string, before: mixed, after: mixed, worsened?: string}
 * @phpstan-type Verdict array{schema: string, id?: string, message: array{received_at: string, from: string, subject: string, message_id: string, size_bytes: int}, publication?: string, verdict: string, ready_to_send: bool, summary: string, top_fixes: list<array{check: string, who: string, fix: string}>, checks: list<Check>, changes: list<Change>, fingerprint?: array<string, mixed>, explanation: string|null, note: string}
 */
final class SendScore
{
    /**
     * Checks one message. A message that fails checks is still a report; this
     * throws only when no report could be made. Pass ['stdin' => true] to
     * give the message's bytes instead of a path.
     *
     * @param array{stdin?: bool, offline?: bool, links?: bool, ip?: string, mailFrom?: string, helo?: string, tls?: bool, previous?: string} $options
     * @return array<string, mixed>
     */
    public static function check(string $message, array $options = []): array
    {
        $args = ['check', '--json'];
        if ($options['offline'] ?? false) {
            $args[] = '--offline';
        }
        if ($options['links'] ?? false) {
            $args[] = '--links';
        }
        foreach (['ip' => '--ip', 'mailFrom' => '--mail-from', 'helo' => '--helo', 'previous' => '--previous'] as $key => $flag) {
            if (isset($options[$key])) {
                array_push($args, $flag, $options[$key]);
            }
        }
        if (isset($options['tls'])) {
            array_push($args, '--tls', $options['tls'] ? 'yes' : 'no');
        }
        $stdin = ($options['stdin'] ?? false) ? $message : null;
        array_push($args, '--', $stdin === null ? $message : '-');
        return self::run($args, $stdin, [0, 1, 2]);
    }

    /**
     * Compares two saved messages, given as paths.
     *
     * @return array<string, mixed>
     */
    public static function diff(string $before, string $after): array
    {
        $result = self::run(['diff', '--json', '--', $before, $after], null, [0, 1]);
        $result['changes'] ??= [];
        return $result;
    }

    /**
     * @param list<string> $args
     * @param list<int> $verdictCodes
     * @return array<string, mixed>
     */
    private static function run(array $args, ?string $stdin, array $verdictCodes): array
    {
        $binary = Binary::find();
        // An array command runs the program directly, with no shell.
        $process = @proc_open(array_merge([$binary], $args), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($process)) {
            throw new SendScoreException("could not run $binary");
        }
        [$stdout, $stderr] = self::pump($pipes, $stdin ?? '');
        $code = proc_close($process);
        if (!in_array($code, $verdictCodes, true)) {
            throw new SendScoreException(trim($stderr) ?: "sendscore exited $code", $code);
        }
        $result = json_decode($stdout, true);
        if (!is_array($result)) {
            throw new SendScoreException('sendscore printed something that is not JSON', $code);
        }
        return $result;
    }

    /**
     * Writes stdin and reads both outputs together, since a large message on
     * one pipe would otherwise deadlock against a full pipe on another.
     *
     * @param array<int, resource> $pipes
     * @return array{0: string, 1: string}
     */
    private static function pump(array $pipes, string $stdin): array
    {
        stream_set_blocking($pipes[0], false);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = ['', ''];
        $written = 0;
        $open = [1 => $pipes[1], 2 => $pipes[2]];
        $in = $pipes[0];
        if ($stdin === '') {
            fclose($in);
            $in = null;
        }
        while ($open !== [] || $in !== null) {
            $read = array_values($open);
            $write = $in === null ? [] : [$in];
            $except = [];
            if (stream_select($read, $write, $except, 30) === false) {
                break;
            }
            if ($write !== []) {
                $n = @fwrite($in, substr($stdin, $written, 65536));
                if ($n === false || $n === 0 && feof($in)) {
                    $written = strlen($stdin);
                } else {
                    $written += $n;
                }
                if ($written >= strlen($stdin)) {
                    fclose($in);
                    $in = null;
                }
            }
            foreach ($read as $stream) {
                $index = array_search($stream, $open, true);
                $chunk = fread($stream, 65536);
                if ($chunk !== false && $chunk !== '') {
                    $out[$index - 1] .= $chunk;
                } elseif (feof($stream)) {
                    fclose($stream);
                    unset($open[$index]);
                }
            }
        }
        return $out;
    }
}
