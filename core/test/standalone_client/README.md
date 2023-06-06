## Standalone VPN client

The VPN client works in two modes:
* SOCKS5 proxy server
* TUN device

See the [example configuration file](./standalone_client.toml) for the set of available options.

### Command line arguments

To select a configuration file other than the default one, pass its name in the command line arguments:

    --config=FILENAME, -c FILENAME

You can also override some parameters from the configuration file through the command line, for example:

* The logging level: `--loglevel=LOGGING_LEVEL, -l LOGGING_LEVEL`,
* Skip certificate verification: `-s`.

To see the full set of available options, run it with `--help`.
