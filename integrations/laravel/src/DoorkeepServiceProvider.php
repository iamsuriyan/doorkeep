<?php

declare(strict_types=1);

namespace Doorkeep\Laravel;

use Doorkeep\Verifier;
use Illuminate\Support\ServiceProvider;

final class DoorkeepServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/doorkeep.php', 'doorkeep');
        $this->app->singleton(Verifier::class, function ($app) {
            $c = $app['config']['doorkeep'];
            if (empty($c['secret'])) {
                throw new \RuntimeException('doorkeep: set DOORKEEP_SECRET');
            }
            return new Verifier((string) $c['url'], (string) $c['secret'], (bool) $c['fail_open'], (int) $c['timeout']);
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__ . '/../config/doorkeep.php' => $this->app->configPath('doorkeep.php')], 'doorkeep-config');
        $this->app['router']->aliasMiddleware('doorkeep', Http\Middleware\VerifyDoorkeep::class);
    }
}
