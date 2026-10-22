<?php

declare(strict_types=1);

namespace Doorkeep;

/** Thrown by Verifier::verify when doorkeep cannot be reached and failOpen is off. */
final class UnavailableException extends \RuntimeException {}
