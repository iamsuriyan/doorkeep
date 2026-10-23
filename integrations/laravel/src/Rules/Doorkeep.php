<?php

declare(strict_types=1);

namespace Doorkeep\Laravel\Rules;

use Closure;
use Doorkeep\UnavailableException;
use Doorkeep\Verifier;
use Illuminate\Contracts\Validation\ValidationRule;

/**
 * Validates a doorkeep token:
 *
 *   $request->validate(['dk-response' => ['required', new Doorkeep('signup')]]);
 *
 * The verify result is kept in $rule->result for logging or your own threshold.
 */
final class Doorkeep implements ValidationRule
{
    public ?array $result = null;

    public function __construct(
        private string $action = '',
        private ?string $remoteIp = null,
        private ?Verifier $verifier = null,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $verifier = $this->verifier ?? app(Verifier::class);
        $ip = $this->remoteIp ?? (function_exists('request') ? request()->ip() : null);
        try {
            $this->result = $verifier->verify(is_string($value) ? $value : '', array_filter(['action' => $this->action, 'remoteip' => $ip]));
        } catch (UnavailableException) {
            $fail('We could not verify this request right now. Please try again.');
            return;
        }
        if (empty($this->result['success'])) {
            $fail('We could not verify this request. Please try again.');
        }
    }
}
