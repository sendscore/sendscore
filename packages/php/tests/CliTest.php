<?php

declare(strict_types=1);

namespace SendScore\Tests;

use PHPUnit\Framework\TestCase;
use SendScore\Binary;
use SendScore\Process;
use SendScore\SendScore;
use SendScore\SendScoreException;

final class CliTest extends TestCase
{
    private const SAMPLE = __DIR__ . '/../../../conformance/messages/clean.eml';

    private static string $tmp;
    private static string $built;
    private static string $exe;
    /** @var array<string, string|false> */
    private array $saved = [];

    public static function setUpBeforeClass(): void
    {
        self::$exe = PHP_OS_FAMILY === 'Windows' ? 'sendscore.exe' : 'sendscore';
        self::$tmp = sys_get_temp_dir() . '/sendscore-cli-' . bin2hex(random_bytes(6));
        self::$built = self::$tmp . '/built/' . self::$exe;
        mkdir(dirname(self::$built), 0777, true);
        $cwd = getcwd();
        chdir(__DIR__ . '/../../..');
        exec('go build -o ' . escapeshellarg(self::$built) . ' ./conformance/fakecli', $out, $code);
        chdir($cwd);
        self::assertSame(0, $code);
    }

    protected function setUp(): void
    {
        foreach (['SENDSCORE_BIN', 'PATH', 'HOME', 'XDG_CACHE_HOME', 'LOCALAPPDATA'] as $key) {
            $this->saved[$key] = getenv($key);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->saved as $key => $value) {
            putenv($value === false ? $key : "$key=$value");
        }
    }

    private function fake(string $mode): string
    {
        $dir = self::$tmp . "/$mode";
        @mkdir($dir);
        copy(self::$built, "$dir/" . self::$exe);
        chmod("$dir/" . self::$exe, 0755);
        return "$dir/" . self::$exe;
    }

    private function onlyPath(string $path): void
    {
        putenv('SENDSCORE_BIN');
        putenv("PATH=$path");
        putenv('HOME=' . self::$tmp . '/home');
        putenv('XDG_CACHE_HOME=' . self::$tmp . '/cache');
        putenv('LOCALAPPDATA=' . self::$tmp . '/cache');
    }

    public function testATimeoutKillsTheCli(): void
    {
        putenv('SENDSCORE_BIN=' . $this->fake('hang'));
        foreach ([
            fn () => SendScore::check(self::SAMPLE, ['timeout' => 0.2]),
            fn () => SendScore::diff(self::SAMPLE, self::SAMPLE, ['timeout' => 0.2]),
        ] as $call) {
            try {
                $call();
                $this->fail('expected a timeout');
            } catch (SendScoreException $e) {
                $this->assertSame(SendScoreException::KILLED, $e->getCode());
            }
        }
    }

    public function testAKilledCliHasOneExitCode(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('no signals');
        }
        putenv('SENDSCORE_BIN=' . $this->fake('killed'));
        try {
            SendScore::check(self::SAMPLE);
            $this->fail('expected an error');
        } catch (SendScoreException $e) {
            $this->assertSame(SendScoreException::KILLED, $e->getCode());
        }
    }

    public function testOutputThatIsNotAVerdictIsRefused(): void
    {
        putenv('SENDSCORE_BIN=' . $this->fake('planted'));
        $this->expectException(SendScoreException::class);
        SendScore::check(self::SAMPLE);
    }

    public function testOutputThatIsNotAComparisonIsRefused(): void
    {
        putenv('SENDSCORE_BIN=' . $this->fake('planted'));
        $this->expectException(SendScoreException::class);
        SendScore::diff(self::SAMPLE, self::SAMPLE);
    }

    public function testUnknownFieldsAndStderrAreTolerated(): void
    {
        putenv('SENDSCORE_BIN=' . $this->fake('noisy'));
        $got = SendScore::check(self::SAMPLE);
        $this->assertSame('pass', $got['verdict']);
        $this->assertSame('brand_new', $got['checks'][0]['status']);
    }

    public function testAWrongVersionOnPathIsNotRun(): void
    {
        $this->fake('version-9.9.9');
        $this->onlyPath(self::$tmp . '/version-9.9.9');
        $this->expectExceptionMessage('no pinned hash');
        Binary::find();
    }

    public function testThePinnedVersionOnPathIsUsed(): void
    {
        $mode = 'version-' . Binary::ENGINE_VERSION;
        $path = $this->fake($mode);
        $this->onlyPath(self::$tmp . "/$mode");
        $this->assertSame(self::$tmp . "/$mode", getenv('PATH'));
        $this->assertTrue(is_file(self::$tmp . "/$mode" . DIRECTORY_SEPARATOR . self::$exe));
        $this->assertSame([0, 'sendscore version ' . Binary::ENGINE_VERSION], array_slice(array_map(
            fn ($v) => is_string($v) ? trim($v) : $v,
            Process::run([self::$tmp . "/$mode" . DIRECTORY_SEPARATOR . self::$exe, '--version'], null, 10.0),
        ), 0, 2));
        $this->assertSame(realpath($path), realpath(Binary::find()));
    }

    public function testRelativePathEntriesAreSkipped(): void
    {
        $mode = 'version-' . Binary::ENGINE_VERSION;
        @mkdir($mode);
        copy($this->fake($mode), "$mode/" . self::$exe);
        chmod("$mode/" . self::$exe, 0755);
        $this->onlyPath(PATH_SEPARATOR . $mode);
        try {
            Binary::find();
            $this->fail('expected no CLI to be found');
        } catch (SendScoreException $e) {
            $this->assertStringContainsString('no pinned hash', $e->getMessage());
        } finally {
            unlink("$mode/" . self::$exe);
            rmdir($mode);
        }
    }

    public function testPathsThatLookLikeFlagsAreFiles(): void
    {
        $real = getenv('SENDSCORE_BIN');
        $this->assertNotFalse($real, 'set SENDSCORE_BIN to a built CLI');
        foreach (['-', '-dash.eml'] as $name) {
            copy(self::SAMPLE, $name);
            try {
                $this->assertNotSame('', SendScore::check($name, ['offline' => true])['message']['subject']);
            } finally {
                unlink($name);
            }
        }
    }

    public function testLargeStdinAndOutputDoNotDeadlock(): void
    {
        $raw = (string) file_get_contents(self::SAMPLE);
        $this->assertNotSame('', SendScore::check($raw . str_repeat("<p>x</p>\n", 200000), ['stdin' => true, 'offline' => true])['verdict']);
    }
}
