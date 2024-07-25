# quickauth

A Simple Authentication Proxy with Basic Web UI

## Environment Variables

- `QUICKAUTH_LISTEN`: The listening address to listen on. Default is `:80`.
- `QUICKAUTH_TARGET`: The target address to proxy to.
- `QUICKAUTH_TARGET_INSECURE`: Whether to ignore the certificate verification of the target. Default is `false`.
- `QUICKAUTH_USERNAME`: The username for authentication.
- `QUICKAUTH_PASSWORD`: The password for authentication.
- `QUICLKAUTH_SECRET_KEY`: The secret key for cookie signing.
- `QUICKAUTH_TITLE`: The title of the web page. Default is `Protected By QuickAuth`.

## Credits

GUO YANKE, MIT License
