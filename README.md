# bimini

Container init process, based on [tini]:[1], which includes [Hashicorp Vault]:[2]
secrets injection into the running environment.

Like Tini, Bimini spawns a single child process while handling zombie process
reaping and signal forwarding. Additionally, on startup it searches the
environment for specially formatted variables which is resolves into values
from [Hashicorp Vault]:[2].

## Usage

Add bimini to your container image and make it executable. Then, invoke the
executable via `ENTRYPOINT`, passing your actual program as arguments:

```dockerfile

ARG bimini_version=0.4.1

### Add bimini
ADD "https://github.com/trialspark/bimini/releases/download/v${bimini_version}/bimini-${TARGETARCH}-unknown-linux-gnu" /sbin/bimini
RUN chmod +x /sbin/bimini

### Configure execution
ENTRYPOINT ["/sbin/bimini', "--"]
CMD ["/path/to/your/binary", "--arg", ... ]
```

## Configuration

bimini is configured by environment variables. The configuration variables are
broken into three groups prefixed by:

- `BIMINI_`
- `AWS_`
- `VAULT_`

See `bimini --help` for information.

[1]: https://github.com/krallin/tini
[2]: https://github.com/hashicorp/vault
