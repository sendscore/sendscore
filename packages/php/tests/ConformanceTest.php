<?php

declare(strict_types=1);

namespace SendScore\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SendScore\SendScore;
use SendScore\SendScoreException;

final class ConformanceTest extends TestCase
{
    private const ROOT = __DIR__ . '/../../../conformance/';

    public static function cases(): array
    {
        $file = json_decode((string) file_get_contents(self::ROOT . 'cases.json'), true);
        $out = [];
        foreach ($file['cases'] as $c) {
            $out[$c['name']] = [$c];
        }
        return $out;
    }

    private function run_(array $c): array
    {
        if ($c['command'] === 'diff') {
            return SendScore::diff(self::ROOT . $c['before'], self::ROOT . $c['after']);
        }
        $given = $c['options'] ?? [];
        $options = ['offline' => true];
        foreach (['links' => 'links', 'ip' => 'ip', 'helo' => 'helo', 'tls' => 'tls', 'mail_from' => 'mailFrom'] as $from => $to) {
            if (array_key_exists($from, $given)) {
                $options[$to] = $given[$from];
            }
        }
        if (isset($given['previous'])) {
            $options['previous'] = self::ROOT . $given['previous'];
        }
        $path = self::ROOT . $c['message'];
        if ($c['via'] === 'stdin') {
            return SendScore::check((string) file_get_contents($path), $options + ['stdin' => true]);
        }
        return SendScore::check($path, $options);
    }

    #[DataProvider('cases')]
    public function testCase(array $c): void
    {
        if ($c['exit'] > 2) {
            try {
                $this->run_($c);
                $this->fail('expected an error');
            } catch (SendScoreException $e) {
                $this->assertSame($c['exit'], $e->getCode());
            }
            return;
        }
        $got = $this->run_($c);
        $changes = $got['changes'] ?? [];
        $this->assertSame($c['changes'] ?? [], array_column($changes, 'field'));
        $this->assertSame($c['worsened'] ?? [], array_column($changes, 'worsened'));
        if ($c['command'] === 'diff') {
            return;
        }
        $this->assertSame($c['verdict'], $got['verdict']);
        $this->assertSame($c['ready_to_send'], $got['ready_to_send']);
        $this->assertEquals($c['checks'], array_column($got['checks'], 'status', 'id'));
    }
}
