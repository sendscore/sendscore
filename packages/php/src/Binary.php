<?php

declare(strict_types=1);

namespace SendScore;

/** Finds the CLI, and downloads a release when none is installed. */
final class Binary
{
    public const ENGINE_VERSION = '0.2.0';
    public const RELEASES = 'https://github.com/sendscore/sendscore/releases/download';

    /** SENDSCORE_BIN, then PATH, then the cache, then a download. */
    public static function find(): string
    {
        $fromEnv = getenv('SENDSCORE_BIN');
        if ($fromEnv !== false && $fromEnv !== '') {
            return $fromEnv;
        }
        $exe = PHP_OS_FAMILY === 'Windows' ? 'sendscore.exe' : 'sendscore';
        foreach (explode(PATH_SEPARATOR, (string) getenv('PATH')) as $dir) {
            if ($dir !== '' && is_file("$dir/$exe") && is_executable("$dir/$exe")) {
                return "$dir/$exe";
            }
        }
        $dir = self::cacheRoot() . '/sendscore/' . self::ENGINE_VERSION;
        if (is_executable("$dir/$exe")) {
            return "$dir/$exe";
        }
        return self::download(self::ENGINE_VERSION, self::RELEASES . '/v' . self::ENGINE_VERSION, $dir);
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
            default => (string) (getenv('XDG_CACHE_HOME') ?: "$home/.cache"),
        };
    }

    public static function archiveName(string $version, string $os, string $arch): string
    {
        $ext = $os === 'windows' ? 'zip' : 'tar.gz';
        return "sendscore_{$version}_{$os}_{$arch}.$ext";
    }

    private static function fetch(string $url): string
    {
        $context = stream_context_create(['http' => ['follow_location' => 1, 'max_redirects' => 5, 'timeout' => 60, 'ignore_errors' => false]]);
        $body = @file_get_contents($url, false, $context);
        if ($body === false) {
            throw new SendScoreException("download of $url failed");
        }
        return $body;
    }

    private static function expectedHash(string $checksums, string $name): string
    {
        foreach (explode("\n", $checksums) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if ($parts !== false && count($parts) === 2 && $parts[1] === $name) {
                return strtolower($parts[0]);
            }
        }
        throw new SendScoreException("checksums.txt does not list $name");
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
     * is checked against checksums.txt before anything is extracted, so a
     * binary that does not match never reaches the disk.
     *
     * @param array{0: string, 1: string}|null $target
     */
    public static function download(string $version, string $base, string $dir, ?array $target = null): string
    {
        [$os, $arch] = $target ?? self::platform();
        $exe = $os === 'windows' ? 'sendscore.exe' : 'sendscore';
        $name = self::archiveName($version, $os, $arch);
        $checksums = self::fetch("$base/checksums.txt");
        $archive = self::fetch("$base/$name");
        if (!hash_equals(self::expectedHash($checksums, $name), hash('sha256', $archive))) {
            throw new SendScoreException("$name does not match checksums.txt");
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
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new SendScoreException("could not make $dir");
        }
        $temp = tempnam($dir, '.download-');
        if ($temp === false || file_put_contents($temp, $binary) === false) {
            throw new SendScoreException("could not write to $dir");
        }
        chmod($temp, 0755);
        if (!rename($temp, "$dir/$exe")) {
            unlink($temp);
            throw new SendScoreException("could not write to $dir");
        }
        return "$dir/$exe";
    }
}
