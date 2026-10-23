# doorkeep for Laravel

```sh
composer require doorkeep/laravel
```

`.env`:

```
DOORKEEP_URL=http://127.0.0.1:8080
DOORKEEP_SECRET=dk_sk_...
```

Load the snippet and put the widget in your form (Blade):

```html
<script src="/_dk/v1/dk.js" data-sitekey="dk_pk_..." async defer></script>
<form method="POST" action="/signup">
  @csrf
  ...
  <div class="doorkeep" data-action="signup"></div>
</form>
```

Then either validate the token:

```php
use Doorkeep\Laravel\Rules\Doorkeep;

$request->validate(['dk-response' => ['required', new Doorkeep('signup')]]);
```

or protect the route:

```php
Route::post('/signup', SignupController::class)->middleware('doorkeep:signup');
```

The middleware answers 403 when the check fails and 503 when doorkeep is
unreachable (unless `DOORKEEP_FAIL_OPEN=true`). The verify result is on
`$request->attributes->get('doorkeep')`. Publish the config with
`php artisan vendor:publish --tag=doorkeep-config`.
