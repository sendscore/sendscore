<?php

declare(strict_types=1);

namespace SendScore\Tests;

use PHPUnit\Framework\TestCase;
use SendScore\Binary;
use SendScore\SendScoreException;

final class DownloadTest extends TestCase
{
    /** @var resource */
    private static $server;
    private static string $base;
    private string $tmp;

    public static function setUpBeforeClass(): void
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr(strrchr(stream_socket_get_name($socket, false), ':'), 1);
        fclose($socket);
        $root = realpath(__DIR__ . '/../../../conformance/release');
        self::$server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $root], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
        self::$base = "http://127.0.0.1:$port";
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100000);
        }
    }

    public static function tearDownAfterClass(): void
    {
        proc_terminate(self::$server);
    }

    protected function setUp(): void
    {
        $this->tmp = sys_get_temp_dir() . '/sendscore-' . bin2hex(random_bytes(6));
        mkdir($this->tmp);
    }

    public function testInstallsTheBinaryAndNothingElse(): void
    {
        foreach ([['linux', 'amd64'], ['darwin', 'arm64'], ['windows', 'amd64']] as $i => $target) {
            $dir = "$this->tmp/cache$i";
            $path = Binary::download('0.0.0-test', self::$base . '/good', $dir, $target);
            $this->assertStringContainsString('fake sendscore', (string) file_get_contents($path));
            $this->assertTrue(is_executable($path));
            $this->assertSame([basename($path)], array_values(array_diff(scandir($dir), ['.', '..'])));
            $this->assertFileDoesNotExist("$this->tmp/evil");
        }
    }

    public function testRefusesAMismatch(): void
    {
        try {
            Binary::download('0.0.0-test', self::$base . '/tampered', "$this->tmp/cache", ['linux', 'amd64']);
            $this->fail('expected a refusal');
        } catch (SendScoreException) {
            $this->assertDirectoryDoesNotExist("$this->tmp/cache");
        }
    }

    public function testFailsOnAMissingRelease(): void
    {
        $this->expectException(SendScoreException::class);
        Binary::download('0.0.0-test', self::$base . '/nothing', "$this->tmp/cache", ['linux', 'amd64']);
    }
}
