# Generating a bcrypt password hash

The panel requires a bcrypt password hash with cost 10 to 15. Generate one with the image helper:

```sh
docker run --rm ghcr.io/ydtoloza/wg-easy-port-manager:2.0.0 wgpw 'YOUR_PASSWORD'
```

The command prints a value similar to:

```dotenv
PASSWORD_HASH='$2b$12$coPqCsPtcFO.Ab99xylBNOW4.Iu7OOA2/ZIboHN6/oyxca3MWo7fW'
```

Keep the single quotes when placing the value in `.env`. Compose treats single-quoted `.env` values literally, so the `$` characters are not interpreted as variable references.

The application also requires a persistent session secret:

```sh
openssl rand -hex 32
```

Store the result as `SESSION_SECRET` in `.env`. Never commit either value.

If a hash is written directly inside a Compose YAML file instead of `.env`, every `$` must be escaped as `$$`. The provided deployment uses `.env`, so this alternate form is not needed.
