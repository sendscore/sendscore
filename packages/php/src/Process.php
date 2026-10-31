<?php

declare(strict_types=1);

namespace SendScore;

/**
 * Runs a program directly, with no shell. Standard streams go through private
 * temporary files, because stream_select does not work on proc_open pipes on
 * Windows, and a file cannot deadlock against a full pipe.
 */
final class Process
{
    /**
     * @param non-empty-list<string> $command
     * @return array{0: int, 1: string, 2: string} the exit code, stdout, and stderr
     */
    public static function run(array $command, ?string $stdin, ?float $timeout): array
    {
        $files = [self::temp(), self::temp(), self::temp()];
        try {
            if ($stdin !== null && file_put_contents($files[0], $stdin) === false) {
                throw new SendScoreException('could not write a temporary file');
            }
            $spec = [0 => ['file', $files[0], 'r'], 1 => ['file', $files[1], 'w'], 2 => ['file', $files[2], 'w']];
            $process = @proc_open($command, $spec, $pipes);
            if (!is_resource($process)) {
                throw new SendScoreException("could not run $command[0]");
            }
            $deadline = $timeout === null ? null : microtime(true) + $timeout;
            while (true) {
                $status = proc_get_status($process);
                if (!$status['running']) {
                    break;
                }
                if ($deadline !== null && microtime(true) >= $deadline) {
                    proc_terminate($process, 9);
                    while (proc_get_status($process)['running']) {
                        usleep(5000);
                    }
                    proc_close($process);
                    throw new SendScoreException("sendscore did not finish within $timeout seconds", SendScoreException::KILLED);
                }
                usleep(5000);
            }
            proc_close($process);
            $code = $status['signaled'] || $status['exitcode'] < 0 || $status['exitcode'] >= 128
                ? SendScoreException::KILLED
                : $status['exitcode'];
            return [$code, (string) file_get_contents($files[1]), (string) file_get_contents($files[2])];
        } finally {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
    }

    private static function temp(): string
    {
        $file = tempnam(sys_get_temp_dir(), 'sendscore-');
        if ($file === false) {
            throw new SendScoreException('could not make a temporary file');
        }
        return $file;
    }
}
