<?php

declare(strict_types=1);

namespace SendScore;

/**
 * The CLI could not produce a report, or could not be found or installed.
 * getCode() is the CLI's exit code: 64 and above, 0 when the CLI never ran,
 * or KILLED.
 */
class SendScoreException extends \RuntimeException
{
    /** The code of a CLI that was killed, or stopped by a timeout. */
    public const KILLED = -1;
}
