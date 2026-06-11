# Authelia Policy Builder

A simple standalone PHP web tool to generate `access_control` YAML rules for Authelia.

The goal is to give self-hosters a small folder they can drop onto any PHP-enabled web server, fill in a form, and copy the generated YAML into their Authelia configuration.

## Features

- Single-page form.
- Set `default_policy` (`deny`, `bypass`, `one_factor`, `two_factor`).
- Paste existing `access_control` YAML and merge new rules into the correct order.
- Add multiple access-control rules:
  - `domain`
  - `policy`
  - optional `users` (comma-separated, without `user:`)
  - optional `groups` (comma-separated, without `group:`)
  - optional `resources`, paths, or keywords
- Friendly resource/path input:
  - `cloud` becomes `^/cloud([/?].*)?$`
  - `/admin` becomes `^/admin([/?].*)?$`
  - `/cloud/admin.php` becomes `^/cloud/admin.php([/?].*)?$`
  - `regex:^/custom.*$` keeps the raw regex
  - `^/raw.*$` keeps the raw regex
- Automatically sorts rules into a safer Authelia order.
- Remove rules.
- Generate YAML in a large copyable textarea.
- Copy YAML button.
- Clear Form button.
- No external dependencies, no database, no Docker, no APIs.

## Usage

1. Place `index.php` and `style.css` in a folder on any PHP-enabled web server.
2. Open `index.php` in your browser.
3. Set the default policy.
4. Optional: paste your current `access_control` YAML into the Existing YAML box.
5. Add one or more new rules.
6. Click **Generate YAML**.
7. Use **Copy YAML** to copy the output.
8. Replace your old `access_control` block with the generated merged output.

## Important: Rule Order Matters

Authelia evaluates access-control rules from top to bottom and uses the first matching rule.

Because of that, restricted paths and folders must appear before broader bypass rules.

The builder automatically sorts generated rules in this order:

1. Protected folders/resources
2. Protected exact subdomains
3. Public exact-domain bypass rules
4. Wildcard/catch-all rules

## Example

Input rules:

```text
tech.example.com / cloud / one_factor / group Family
tech.example.com / cloud/admin.php / deny / group Family
tech.example.com / cloud/admin.php / one_factor / group Admin
tech.example.com / bypass
kitchen.example.com / one_factor / group Family
*.example.com / bypass
```

Generated YAML:

```yaml
access_control:
  default_policy: deny

  rules:
    - domain: "tech.example.com"
      resources:
        - "^/cloud/admin.php([/?].*)?$"
      policy: deny
      subject:
        - "group:Family"

    - domain: "tech.example.com"
      resources:
        - "^/cloud/admin.php([/?].*)?$"
      policy: one_factor
      subject:
        - "group:Admin"

    - domain: "tech.example.com"
      resources:
        - "^/cloud([/?].*)?$"
      policy: one_factor
      subject:
        - "group:Family"

    - domain: "kitchen.example.com"
      policy: one_factor
      subject:
        - "group:Family"

    - domain: "tech.example.com"
      policy: bypass

    - domain: "*.example.com"
      policy: bypass
```

## Policies

- `bypass` – no login required
- `deny` – blocks access
- `one_factor` – requires login
- `two_factor` – requires login plus 2FA

## Resource / Path Input

You do not have to write regex manually for simple paths.

Examples:

```text
cloud
/admin
/cloud/admin.php
```

Output:

```yaml
resources:
  - "^/cloud([/?].*)?$"
  - "^/admin([/?].*)?$"
  - "^/cloud/admin.php([/?].*)?$"
```

For advanced users, raw regex is still supported:

```text
regex:^/admin.*$
^/private.*$
```

## Groups

Group input:

```text
Family, Admin
```

Output:

```yaml
subject:
  - "group:Family"
  - "group:Admin"
```

You can enter groups with or without `group:`. The builder will normalise them.

## Users

User input:

```text
rik, alice
```

Output:

```yaml
subject:
  - "user:rik"
  - "user:alice"
```

You can enter users with or without `user:`. The builder will normalise them.

## Warning

This tool generates YAML but does not validate your final Authelia configuration.

Always test your configuration and verify access policies after applying changes to Authelia.


## Deny Before Allow

Authelia uses the first matching rule. If two rules match the same domain and resource, place `deny` before `one_factor` or `two_factor`.

Example:

```yaml
- domain: "tech.example.com"
  resources:
    - "^/cloud/admin.php([/?].*)?$"
  policy: deny
  subject:
    - "group:Family"

- domain: "tech.example.com"
  resources:
    - "^/cloud/admin.php([/?].*)?$"
  policy: one_factor
  subject:
    - "group:Admin"
```

This prevents a broader allow rule from granting access before the deny rule is checked.


## Nginx Proxy Manager .

I use the following settings in the advance tab to make authelia work with NPM (only put in the hosts you want to protect.)


```php
auth_request /api/verify;
auth_request_set $redirection_url $upstream_http_location;
error_page 401 =302 $redirection_url;

auth_request_set $user $upstream_http_remote_user;
auth_request_set $groups $upstream_http_remote_groups;
auth_request_set $name $upstream_http_remote_name;
auth_request_set $email $upstream_http_remote_email;

proxy_set_header Remote-User $user;
proxy_set_header Remote-Groups $groups;
proxy_set_header Remote-Name $name;
proxy_set_header Remote-Email $email;

location /api/verify {
    internal;
    proxy_pass http://authelia:9091/api/authz/auth-request;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";

    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-URL $scheme://$host$request_uri;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-URI $request_uri;
    proxy_set_header X-Forwarded-For $remote_addr;
}
```

