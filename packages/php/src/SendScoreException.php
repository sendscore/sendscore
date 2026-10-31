<?php

declare(strict_types=1);

namespace SendScore;

/**
 * The CLI could not produce a report, or could not be found or installed.
 * getCode() is the CLI's exit code: 64 and above, or 0 when the CLI never ran.
 */
class SendScoreException extends \RuntimeException
{
}
