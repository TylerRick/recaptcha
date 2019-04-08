# reCAPTCHA

Author:    Jason L Perry (http://ambethia.com)<br/>
Copyright: Copyright (c) 2007-2013 Jason L Perry<br/>
License:   [MIT](http://creativecommons.org/licenses/MIT/)<br/>
Info:      https://github.com/ambethia/recaptcha<br/>
Bugs:      https://github.com/ambethia/recaptcha/issues<br/>

This plugin adds helpers for the [reCAPTCHA API](https://www.google.com/recaptcha). In your
views you can use the `recaptcha_tags` method to embed the needed javascript,
and you can validate in your controllers with `verify_recaptcha` or `verify_recaptcha!`,
which throws an error on failiure.

## Obtaining a key

Go to the [reCAPTCHA admin console](https://www.google.com/recaptcha/admin) to obtain a reCAPTCHA API key.

The reCAPTCHA type that you choose for your key will determine which methods to use below.

| reCAPTCHA type      | Methods to use | Description |
|---------------------|----------------|-------------|
| v3      | [`recaptcha_v3`](#recaptcha_v3)<br/>[`verify_recaptcha_v3`](#verify_recaptcha_v3) | Verify requests with a score
| v2 Checkbox<br/>("I'm not a robot" Checkbox) | [`recaptcha_tags`](#recaptcha_tags)<br/>[`verify_recaptcha_v2`](#verify_recaptcha-verify_recaptcha_v2) | Verify requests with a challenge: Validate requests with the "I'm not a robot" checkbox |
| v2 Invisible<br/>(Invisible reCAPTCHA badge) | [`invisible_recaptcha_tags`](#invisible_recaptcha_tags)<br/>[`verify_recaptcha_v2`](#verify_recaptcha-verify_recaptcha_v2) | Verify requests with a challenge: Validate requests in the background |

Note: You can _only_ use methods that match your key's type. You cannot use v2 methods with a v3
key, for example. Otherwise you will get "ERROR for site owner: Invalid key type".

Note: Use `localhost` or `127.0.0.1` in domain if using in development with `localhost:3000`.

## Rails Installation

```Ruby
gem "recaptcha"
```

Keep keys out of the code base with environment variables.<br/>
Set in production and locally use [dotenv](https://github.com/bkeepers/dotenv), make sure to add it above recaptcha.

Otherwise see [Alternative API key setup](#alternative-api-key-setup).

```
export RECAPTCHA_SITE_KEY  = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyyy'
export RECAPTCHA_SECRET_KEY = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxxx'
```

Add `recaptcha_tags` to the forms you want to protect.

```Erb
<%= form_for @foo do |f| %>
  # ... other tags
  <%= recaptcha_tags %>
  # ... other tags
<% end %>
```

And, add `verify_recaptcha` logic to each form action that you've protected.

```Ruby
# app/controllers/users_controller.rb
@user = User.new(params[:user].permit(:name))
if verify_recaptcha(model: @user) && @user.save
  redirect_to @user
else
  render 'new'
end
```

## Sinatra / Rack / Ruby installation

See [sinatra demo](/demo/sinatra) for details.

 - add `gem 'recaptcha'` to `Gemfile`
 - set env variables
 - `include Recaptcha::ClientHelper` where you need `recaptcha_tags`
 - `include Recaptcha::Verify` where you need `verify_recaptcha`

## `recaptcha_tags`

Use this when your key's reCAPTCHA type is "v2 Checkbox".

The following options are available:

| Option              | Description |
|---------------------|-------------|
| `:theme`            | Specify the theme to be used per the API. Available options: `dark` and `light`. (default `light`) |
| `:ajax`             | Render the dynamic AJAX captcha per the API. (default `false`) |
| `:site_key`         | Override site API key from configuration |
| `:error`            | Override the error code returned from the reCAPTCHA API (default `nil`) |
| `:size`             | Specify a size (default `nil`) |
| `:nonce`            | Optional. Sets nonce attribute for script. Can be generated via `SecureRandom.base64(32)`. (default `nil`) |
| `:id`               | Specify an html id attribute (default `nil`) |
| `:callback`         | Optional. Name of success callback function, executed when the user submits a successful response |
| `:expired_callback` | Optional. Name of expiration callback function, executed when the reCAPTCHA response expires and the user needs to re-verify. |
| `:error_callback`   | Optional. Name of error callback function, executed when reCAPTCHA encounters an error (e.g. network connectivity) |
| `:noscript`         | Include <noscript> content (default `true`)|

[JavaScript resource (api.js) parameters](https://developers.google.com/recaptcha/docs/invisible#js_param):

| Option              | Description |
|---------------------|-------------|
| `:onload`           | Optional. The name of your callback function to be executed once all the dependencies have loaded. (See [explicit rendering](https://developers.google.com/recaptcha/docs/display#explicit_render)) |
| `:render`           | Optional. Whether to render the widget explicitly. Defaults to `onload`, which will render the widget in the first g-recaptcha tag it finds. (See [explicit rendering](https://developers.google.com/recaptcha/docs/display#explicit_render)) |
| `:hl`               | Optional. Forces the widget to render in a specific language. Auto-detects the user's language if unspecified. (See [language codes](https://developers.google.com/recaptcha/docs/language)) |
| `:script`           | Alias for `:external_script`. If you do not need to add a script tag by helper you can set the option to `false`. It's necessary when you add a script tag manualy (default `true`). |
| `:external_script`  | Set to `false` to avoid including a script tag for the external `api.js` resource. Useful when including multiple `recaptcha_tags` on the same page. |
| `:script_async`     | Set to `false` to load the external `api.js` resource synchronously. (default: `true`) |
| `:script_defer`     | Set to `true` to defer loading of external `api.js` until HTML documen has been parsed. (default: `true`) |

Any unrecognized options will be added as attributes on the generated tag.

You can also override the html attributes for the sizes of the generated `textarea` and `iframe`
elements, if CSS isn't your thing. Inspect the [source of `recaptcha_tags`](https://github.com/ambethia/recaptcha/blob/master/lib/recaptcha/client_helper.rb)
to see these options.

## `verify_recaptcha` (`verify_recaptcha_v2`)

This method returns `true` or `false` after processing the response token from the reCAPTCHA widget.
This is usually called from your controller, as seen [above](#rails-installation).

Passing in the ActiveRecord object via `model: object` is optional. If you pass a `model`—and the
captcha fails to verify—an error will be added to the object for you to use (available as
`object.errors`).

Why isn't this a model validation? Because that violates MVC. You can use it like this, or how ever
you like.

Some of the options available:

| Option         | Description |
|----------------|-------------|
| `:model`       | Model to set errors.
| `:attribute`   | Model attribute to receive errors. (default `:base`)
| `:message`     | Custom error message.
| `:secret_key`  | Override secret API key.
| `:timeout`     | The number of seconds to wait for reCAPTCHA servers before give up. (default `3`)
| `:response`    | Custom response parameter. (default: `params['g-recaptcha-response']`)
| `:hostname`    | Expected hostname or a callable that validates the hostname, see [domain validation](https://developers.google.com/recaptcha/docs/domain_validation) and [hostname](https://developers.google.com/recaptcha/docs/verify#api-response) docs. (default: `nil`, but can be changed by setting `config.hostname`)
| `:env`         | Current environment. The request to verify will be skipped if the environment is specified in configuration under `skip_verify_env`

## `invisible_recaptcha_tags`

Use this when your key's reCAPTCHA type is "v2 Invisible".

For more information, refer to: [Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible).

This is similar to `recaptcha_tags`, with the following additional options that are only available
on `invisible_recaptcha_tags`:

| Option              | Description |
|---------------------|-------------|
| `:ui`               | The type of UI to render for this "invisible" widget. (default: `:button`)<br/>`:button`: Renders a `<button type="submit">` tag with `options[:text]` as the button text.<br/>`:invisible`: Renders a `<div>` tag.<br/>`:input`: Renders a `<input type="submit">` tag with `options[:text]` as the button text. |
| `:text`             | The text to show for the button. (default: `"Submit"`)
| `:inline_script`    | If you do not need this helper to add an inline script tag, you can set the option to `false` (default `true`).

It also accepts most of the options that `recaptcha_tags` accepts, including the following:

| Option              | Description |
|---------------------|-------------|
| `:site_key`         | Override site API key from configuration` |
| `:nonce`            | Optional. Sets nonce attribute for script tag. Can be generated via `SecureRandom.base64(32)`. (default `nil`) |
| `:id`               | Specify an html id attribute (default `nil`)|
| `:script`           | Same as setting both `:inline_script` and `:external_script`. If you only need one or the other, use `:inline_script` and `:external_script` instead.
| `:callback`         | Optional. Name of success callback function, executed when the user submits a successful response` |
| `:expired_callback` | Optional. Name of expiration callback function, executed when the reCAPTCHA response expires and the user needs to re-verify.` |
| `:error_callback`   | Optional. Name of error callback function, executed when reCAPTCHA encounters an error (e.g. network connectivity)` |

[JavaScript resource (api.js) parameters](https://developers.google.com/recaptcha/docs/invisible#js_param):

| Option              | Description |
|---------------------|-------------|
| `:onload`           | Optional. The name of your callback function to be executed once all the dependencies have loaded. (See [explicit rendering](https://developers.google.com/recaptcha/docs/display#explicit_render)) |
| `:render`           | Optional. Whether to render the widget explicitly. Defaults to `onload`, which will render the widget in the first g-recaptcha tag it finds. (See [explicit rendering](https://developers.google.com/recaptcha/docs/display#explicit_render)) |
| `:hl`               | Optional. Forces the widget to render in a specific language. Auto-detects the user's language if unspecified. (See [language codes](https://developers.google.com/recaptcha/docs/language)) |
| `:external_script`  | Set to `false` to avoid including a script tag for the external `api.js` resource. Useful when including multiple `recaptcha_tags` on the same page. |
| `:script_async`     | Set to `false` to load the external `api.js` resource synchronously. (default: `true`) |
| `:script_defer`     | Set to `false` to defer loading of external `api.js` until HTML documen has been parsed. (default: `true`) |

### With a single form on a page

1. The `invisible_recaptcha_tags` generates a submit button for you.

```Erb
<%= form_for @foo do |f| %>
  # ... other tags
  <%= invisible_recaptcha_tags text: 'Submit form' %>
<% end %>
```

Then, add `verify_recaptcha` to your controller as seen [above](#rails-installation).

### With multiple forms on a page

1. You will need a custom callback function, which is called after verification with Google's reCAPTCHA service. This callback function must submit the form. Optionally, `invisible_recaptcha_tags` currently implements a JS function called `invisibleRecaptchaSubmit` that is called when no `callback` is passed. Should you wish to override `invisibleRecaptchaSubmit`, you will need to use `invisible_recaptcha_tags script: false`, see lib/recaptcha/client_helper.rb for details.
2. The `invisible_recaptcha_tags` generates a submit button for you.

```Erb
<%= form_for @foo, html: {id: 'invisible-recaptcha-form'} do |f| %>
  # ... other tags
  <%= invisible_recaptcha_tags callback: 'submitInvisibleRecaptchaForm', text: 'Submit form' %>
<% end %>
```

```Javascript
// app/assets/javascripts/application.js
var submitInvisibleRecaptchaForm = function () {
  document.getElementById("invisible-recaptcha-form").submit();
};
```

Finally, add `verify_recaptcha` to your controller as seen [above](#rails-installation).

### Programmatically invoke

1. Specify `ui` option

```Erb
<%= form_for @foo, html: {id: 'invisible-recaptcha-form'} do |f| %>
  # ... other tags
  <button type="button" id="submit-btn">
    Submit
  </button>
  <%= invisible_recaptcha_tags ui: :invisible, callback: 'submitInvisibleRecaptchaForm' %>
<% end %>
```

```Javascript
// app/assets/javascripts/application.js
document.getElementById('submit-btn').addEventListener('click', function (e) {
  // do some validation
  if(isValid) {
    // call reCAPTCHA check
    grecaptcha.execute();
  }
});

var submitInvisibleRecaptchaForm = function () {
  document.getElementById("invisible-recaptcha-form").submit();
};
```


## reCAPTCHA v3

The main differences from v2 are:
1. the result is not a simple boolean "success" or "failure"; rather, it is a score from 0.0 to 1.0
1. you must specify an [action](https://developers.google.com/recaptcha/docs/v3#actions) in both frontend and backend
1. it only supports executing reCAPTCHA invisibly; there is no option for a visible UI.

For more information, refer to the [v3 documentation](https://developers.google.com/recaptcha/docs/v3).

### Example

```erb
<%= form_for @user do |f| %>
  …
  <%= recaptcha_v3(action: 'registration') %>
  …
<% end %>
```

```ruby
# app/controllers/users_controller.rb
@user = User.new(params[:user].permit(:name))
recaptcha_result = verify_recaptcha_v3(model: @user, action: 'registration')
if recaptcha_result && recaptcha_result.valid?
  if recaptcha_result.score > 0.5
    if @user.save
      redirect_to @user
    else
      render 'new'
    end
  else
    # Score is below threshold, so user may be a bot. Show a challenge, require multi-factor
    # authentication, or do something else.
  end
else
  render 'new'
end
```

### `recaptcha_v3`

Adds an inline script tag that calls `grecaptcha.execute` for the given `site_key` and `action` and
calls the `callback` with the resulting response token. You need to verify this token with
[`verify_recaptcha_v3`](#verify_recaptcha_v3) in order to get the score.

This is similar to `recaptcha_tags`/`invisible_recaptcha_tags` but only accepts the following options:

| Option              | Description |
|---------------------|-------------|
| `:site_key`         | Override site API key |
| `:action`           | The name of the [reCAPTCHA action](https://developers.google.com/recaptcha/docs/v3#actions). Actions may only contain alphanumeric characters and slashes, and must not be user-specific. |
| `:nonce`            | Optional. Sets nonce attribute for script. Can be generated via `SecureRandom.base64(32)`. (default `nil`) |
| `:callback`         | Name of callback function to call with the token. When `element` is `:input`, this defaults to a function `setInputWithRecaptchaResponseToken` that sets the value of the hidden input to the token. |
| `:id`               | Specify a unique `id` attribute for the `<input>` element if using `element: :input`. (default is `"g-recaptcha-response-"` + `action`) |
| `:name`             | Specify a unique `name` attribute for the `<input>` element if using `element: :input`. (default is `g-recaptcha-response[action]`) |
| `:script`           | Same as setting both `:inline_script` and `:external_script`. (default `true`). |
| `:inline_script`    | If `true`, adds an inline script tag that calls `grecaptcha.execute` for the given `site_key` and `action` and calls the `callback` with the resulting response token. Pass `false` if you want to handle calling `grecaptcha.execute` yourself. (default `true`) |
| `:element`          | The element to render, if any (default: `:input`)<br/>`:input`: Renders a hidden `<input type="hidden">` tag. The value of this will be set to the resonse token by the default `setInputWithRecaptchaResponseToken` callback.<br/>`false`: Doesn't render any tag. You'll have to add a custom callback that does something with the token. |

[JavaScript resource (api.js) parameters](https://developers.google.com/recaptcha/docs/invisible#js_param):

| Option              | Description |
|---------------------|-------------|
| `:onload`           | Optional. The name of your callback function to be executed once all the dependencies have loaded. (See [explicit rendering](https://developers.google.com/recaptcha/docs/display#explicit_render))|
| `:external_script`  | Set to `false` to avoid including a script tag for the external `api.js` resource. Useful when including multiple `recaptcha_tags` on the same page.
| `:script_async`     | Set to `true` to load the external `api.js` resource asynchronously. (default: `false`) |
| `:script_defer`     | Set to `true` to defer loading of external `api.js` until HTML documen has been parsed. (default: `false`) |

If using `element: :input`, any unrecognized options will be added as attributes on the generated
`<input>` element.

### `verify_recaptcha_v3`

This method verifies response token that was submitted from the frontend. The return value is either
`false` or a `Recaptcha::Verify::VerifyResult` object representing the result.

If it was able to verify the token, the score for the given action (as a number from `0.0` - `1.0`)
is available from the `result` object as `result.score`.

```ruby
result = verify_recaptcha_v3(action: 'action/name')
```

This accepts the same options as [`verify_recaptcha_v2`](#verify_recaptcha-verify_recaptcha_v2), plus:

| Option         | Description |
|----------------|-------------|
| `:action`      | The name of the [reCAPTCHA action](https://developers.google.com/recaptcha/docs/v3#actions) that we are verifying. Set to `false` to skip verifying that the action matches.

### Multiple actions on the same page

According to https://developers.google.com/recaptcha/docs/v3#placement,

> Note: You can execute reCAPTCHA as many times as you'd like with different actions on the same page.

You will need to verify each action individually with separate call to `verify_recaptcha_v3`.

```ruby
result_a = verify_recaptcha_v3(action: 'a')
result_b = verify_recaptcha_v3(action: 'b')
```

Because the response tokens for multiple actions may be submitted together in the same request, they
are passed as a hash under `params['g-recaptcha-response']` with the action as the key.

It is recommended to pass `external_script: false` on all but one of the calls to
`recaptcha_v3` since you only need to include the script tag once for a given `site_key`.

### Mixing v2 and v3 in an app

It is possible to use both v2 and v3 in the same app. https://developers.google.com/recaptcha/docs/faq#should-i-use-recaptcha-v2-or-v3.

If you would like to use both v2 and v3 APIs, then you need a different key for each. You can
configure keys for both like this:

```ruby
Recaptcha.configure do |config|
  config.site_key_v2   = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyy2'
  config.secret_key_v2 = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxx2'
  config.site_key_v3   = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyy3'
  config.secret_key_v3 = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxx3'
end
```


## I18n support
reCAPTCHA passes two types of error explanation to a linked model. It will use the I18n gem
to translate the default error message if I18n is available. To customize the messages to your locale,
add these keys to your I18n backend:

`recaptcha.errors.verification_failed` error message displayed if the captcha words didn't match
`recaptcha.errors.recaptcha_unreachable` displayed if a timeout error occured while attempting to verify the captcha

Also you can translate API response errors to human friendly by adding translations to the locale (`config/locales/en.yml`):

```Yaml
en:
  recaptcha:
    errors:
      verification_failed: 'Fail'
```

## Testing

By default, reCAPTCHA is skipped in "test" and "cucumber" env. To enable it during test:

```Ruby
Recaptcha.configuration.skip_verify_env.delete("test")
```

## Alternative API key setup

### Recaptcha.configure

```Ruby
# config/initializers/recaptcha.rb
Recaptcha.configure do |config|
  config.site_key  = '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyyy'
  config.secret_key = '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxxx'
  # Uncomment the following line if you are using a proxy server:
  # config.proxy = 'http://myproxy.com.au:8080'
end
```

### Recaptcha.with_configuration

For temporary overwrites (not thread safe).

```Ruby
Recaptcha.with_configuration(site_key: '12345') do
  # Do stuff with the overwritten site_key.
end
```

### Per call

Pass in keys as options at runtime, for code base with multiple reCAPTCHA setups:

```Ruby
recaptcha_tags site_key: '6Lc6BAAAAAAAAChqRbQZcn_yyyyyyyyyyyyyyyyy'

# and

verify_recaptcha secret_key: '6Lc6BAAAAAAAAKN3DRm6VA_xxxxxxxxxxxxxxxxx'
```

## Misc
 - Check out the [wiki](https://github.com/ambethia/recaptcha/wiki) and leave whatever you found valuable there.
 - [Add multiple widgets to the same page](https://github.com/ambethia/recaptcha/wiki/Add-multiple-widgets-to-the-same-page)
 - [Use Recaptcha with Devise](https://github.com/plataformatec/devise/wiki/How-To:-Use-Recaptcha-with-Devise)
