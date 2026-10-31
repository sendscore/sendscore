<?php

declare(strict_types=1);

namespace SendScore;

/** Finds the CLI, and downloads a release when none is installed. */
final class Binary
{
    public const ENGINE_VERSION = '0.2.0';
    public const RELEASES = 'https://github.com/sendscore/sendscore/releases/download';

    private const MAX_DOWNLOAD = 100 << 20;

    /**
     * SENDSCORE_BIN, then the pinned version on PATH, then the cache, then a
     * download. A cached binary is checked against its pinned hash every time,
     * so a file planted in the cache is replaced and never run.
     */
    public static function find(): string
    {
        $fromEnv = getenv('SENDSCORE_BIN');
        if ($fromEnv !== false && $fromEnv !== '') {
            return $fromEnv;
        }
        $exe = PHP_OS_FAMILY === 'Windows' ? 'sendscore.exe' : 'sendscore';
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            $path = "$dir/$exe";
            if (self::isAbsolute($dir) && is_file($path) && is_executable($path) && self::rightVersion($path)) {
                return $path;
            }
        }
        $target = self::platform();
        $pin = self::pinFor($target[0], $target[1]);
        $dir = self::cacheRoot() . '/sendscore/' . self::ENGINE_VERSION;
        if (self::matchesPin("$dir/$exe", $pin)) {
            return "$dir/$exe";
        }
        return self::download(self::ENGINE_VERSION, self::RELEASES . '/v' . self::ENGINE_VERSION, $dir, $pin, $target);
    }

    private static function isAbsolute(string $path): bool
    {
        if (PHP_OS_FAMILY === 'Windows') {
            return preg_match('/^(?:[A-Za-z]:[\\\/]|\\\\)/', $path) === 1;
        }
        return str_starts_with($path, '/');
    }

    private static function rightVersion(string $path): bool
    {
        try {
            [$code, $stdout] = Process::run([$path, '--version'], null, 10.0);
        } catch (SendScoreException) {
            return false;
        }
        $words = preg_split('/\s+/', trim($stdout));
        return $code === 0 && $words !== false && ltrim((string) end($words), 'v') === self::ENGINE_VERSION;
    }

    /**
     * The archive and binary hashes of a platform. With none, nothing is trusted.
     *
     * @param array<string, array{0: string, 1: string}> $pins
     * @return array{0: string, 1: string}
     */
    public static function pinFor(string $os, string $arch, array $pins = Hashes::PINS): array
    {
        $pin = $pins["{$os}_{$arch}"] ?? null;
        if ($pin === null) {
            throw new SendScoreException("this package has no pinned hash for {$os}_{$arch}, so it will not download a CLI. Install the matching sendscore on PATH, or set SENDSCORE_BIN.");
        }
        return $pin;
    }

    /**
     * Whether a file exists and is exactly the pinned binary.
     *
     * @param array{0: string, 1: string} $pin
     */
    public static function matchesPin(string $path, array $pin): bool
    {
        return is_file($path) && hash_equals($pin[1], (string) hash_file('sha256', $path));
    }

    /** @return array{0: string, 1: string} */
    public static function platform(): array
    {
        $os = ['Linux' => 'linux', 'Darwin' => 'darwin', 'Windows' => 'windows'][PHP_OS_FAMILY] ?? null;
        $arch = ['x86_64' => 'amd64', 'amd64' => 'amd64', 'AMD64' => 'amd64', 'arm64' => 'arm64', 'aarch64' => 'arm64'][php_uname('m')] ?? null;
        if ($os === null || $arch === null) {
            throw new SendScoreException('no SendScore build for ' . PHP_OS_FAMILY . ' on ' . php_uname('m'));
        }
        return [$os, $arch];
    }

    private static function cacheRoot(): string
    {
        $home = (string) (getenv('HOME') ?: getenv('USERPROFILE'));
        return match (PHP_OS_FAMILY) {
            'Darwin' => "$home/Library/Caches",
            'Windows' => (string) (getenv('LOCALAPPDATA') ?: "$home/AppData/Local"),
            default => self::isAbsolute((string) getenv('XDG_CACHE_HOME')) ? (string) getenv('XDG_CACHE_HOME') : "$home/.cache",
        };
    }

    public static function archiveName(string $version, string $os, string $arch): string
    {
        $ext = $os === 'windows' ? 'zip' : 'tar.gz';
        return "sendscore_{$version}_{$os}_{$arch}.$ext";
    }

    private static function fetch(string $url): string
    {
        if (!ini_get('allow_url_fopen')) {
            throw new SendScoreException('downloading the CLI needs allow_url_fopen. Install sendscore on PATH, or set SENDSCORE_BIN.');
        }
        $context = stream_context_create(['http' => ['follow_location' => 1, 'max_redirects' => 5, 'timeout' => 60, 'ignore_errors' => false]]);
        $body = @file_get_contents($url, false, $context, 0, self::MAX_DOWNLOAD + 1);
        if ($body === false) {
            throw new SendScoreException("download of $url failed");
        }
        if (strlen($body) > self::MAX_DOWNLOAD) {
            throw new SendScoreException("download of $url is too large");
        }
        return $body;
    }

    /** Reads one file, by its exact name, from a tar archive. */
    public static function fromTar(string $tar, string $name): ?string
    {
        for ($at = 0; $at + 512 <= strlen($tar);) {
            $header = substr($tar, $at, 512);
            if (trim($header, "\0") === '') {
                return null;
            }
            $entry = rtrim(substr($header, 0, 100), "\0");
            $size = (int) octdec(trim(rtrim(substr($header, 124, 12), "\0 ")));
            $type = $header[156];
            $at += 512;
            if ($entry === $name && ($type === '0' || $type === "\0")) {
                return substr($tar, $at, $size);
            }
            $at += (int) ceil($size / 512) * 512;
        }
        return null;
    }

    /** Reads one file, by its exact name, from a zip archive. */
    public static function fromZip(string $zip, string $name): ?string
    {
        $end = strrpos($zip, "PK\x05\x06");
        if ($end === false) {
            return null;
        }
        $count = unpack('v', $zip, $end + 10)[1];
        $at = unpack('V', $zip, $end + 16)[1];
        for ($i = 0; $i < $count; $i++) {
            $c = unpack('vmethod', $zip, $at + 10) + unpack('Vpacked', $zip, $at + 20)
                + unpack('vname/vextra/vcomment', $zip, $at + 28) + unpack('Vlocal', $zip, $at + 42);
            if (substr($zip, $at + 46, $c['name']) === $name) {
                $l = unpack('vname/vextra', $zip, $c['local'] + 26);
                $data = substr($zip, $c['local'] + 30 + $l['name'] + $l['extra'], $c['packed']);
                if ($c['method'] === 0) {
                    return $data;
                }
                $out = @gzinflate($data);
                return $out === false ? null : $out;
            }
            $at += 46 + $c['name'] + $c['extra'] + $c['comment'];
        }
        return null;
    }

    /**
     * Downloads a release into $dir and returns the binary's path. The archive
     * must match its pin before anything is extracted, and the binary must
     * match its pin before it reaches the disk.
     *
     * @param array{0: string, 1: string} $pin
     * @param array{0: string, 1: string}|null $target
     */
    public static function download(string $version, string $base, string $dir, array $pin, ?array $target = null): string
    {
        [$os, $arch] = $target ?? self::platform();
        $exe = $os === 'windows' ? 'sendscore.exe' : 'sendscore';
        $name = self::archiveName($version, $os, $arch);
        $archive = self::fetch("$base/$name");
        if (!hash_equals($pin[0], hash('sha256', $archive))) {
            throw new SendScoreException("$name does not match its pinned hash");
        }
        if ($os === 'windows') {
            $binary = self::fromZip($archive, $exe);
        } else {
            $tar = @gzdecode($archive);
            $binary = $tar === false ? null : self::fromTar($tar, $exe);
        }
        if ($binary === null) {
            throw new SendScoreException("$name has no $exe");
        }
        if (!hash_equals($pin[1], hash('sha256', $binary))) {
            throw new SendScoreException("the binary in $name does not match its pinned hash");
        }
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new SendScoreException("could not make $dir");
        }
        $temp = @tempnam($dir, '.download-');
        if ($temp === false || @file_put_contents($temp, $binary) === false) {
            throw new SendScoreException("could not write to $dir");
        }
        @chmod($temp, 0755);
        if (!@rename($temp, "$dir/$exe")) {
            @unlink($temp);
            throw new SendScoreException("could not write to $dir");
        }
        return "$dir/$exe";
    }
}
