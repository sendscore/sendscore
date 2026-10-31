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
     * give the message's bytes instead of a path, and ['timeout' => 5.0] to
     * kill the CLI after that many seconds.
     *
     * @param array{stdin?: bool, offline?: bool, links?: bool, ip?: string, mailFrom?: string, helo?: string, tls?: bool, previous?: string, timeout?: float} $options
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
        foreach (['ip' => '--ip', 'mailFrom' => '--mail-from', 'helo' => '--helo'] as $key => $flag) {
            if (isset($options[$key])) {
                array_push($args, $flag, $options[$key]);
            }
        }
        if (isset($options['previous'])) {
            array_push($args, '--previous', self::path($options['previous']));
        }
        if (isset($options['tls'])) {
            array_push($args, '--tls', $options['tls'] ? 'yes' : 'no');
        }
        $stdin = ($options['stdin'] ?? false) ? $message : null;
        array_push($args, '--', $stdin === null ? self::path($message) : '-');
        $result = self::run($args, $stdin, [0, 1, 2], $options['timeout'] ?? null);
        if (!str_starts_with((string) ($result['schema'] ?? ''), 'sendscore.verdict/')) {
            throw new SendScoreException('sendscore printed something that is not a verdict');
        }
        return $result;
    }

    /**
     * Compares two saved messages, given as paths.
     *
     * @param array{timeout?: float} $options
     * @return array<string, mixed>
     */
    public static function diff(string $before, string $after, array $options = []): array
    {
        $args = ['diff', '--json', '--', self::path($before), self::path($after)];
        $result = self::run($args, null, [0, 1], $options['timeout'] ?? null);
        if (!array_key_exists('changes', $result)) {
            throw new SendScoreException('sendscore printed something that is not a comparison');
        }
        $result['changes'] ??= [];
        return $result;
    }

    /** A lone `-` would mean standard input to the CLI. */
    private static function path(string $path): string
    {
        return $path === '-' ? './-' : $path;
    }

    /**
     * @param list<string> $args
     * @param list<int> $verdictCodes
     * @return array<string, mixed>
     */
    private static function run(array $args, ?string $stdin, array $verdictCodes, ?float $timeout): array
    {
        [$code, $stdout, $stderr] = Process::run(array_merge([Binary::find()], $args), $stdin, $timeout);
        if (!in_array($code, $verdictCodes, true)) {
            throw new SendScoreException(trim($stderr) ?: "sendscore exited $code", $code);
        }
        $result = json_decode($stdout, true);
        if (!is_array($result)) {
            throw new SendScoreException('sendscore printed something that is not JSON', $code);
        }
        return $result;
    }
}
