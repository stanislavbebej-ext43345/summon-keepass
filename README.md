[![Build](https://github.com/stanislavbebej-ext43345/summon-keepass/actions/workflows/build.yml/badge.svg)](.github/workflows/build.yml)
[![dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?logo=dependabot)](.github/dependabot.yml)
[![release-please](https://img.shields.io/badge/release--please-enabled-brightgreen?logo=google)](.github/release-please.yml)

# summon-keepass

[KeePass](https://keepass.info) 2 files (kdbx) provider for [Summon](https://github.com/cyberark/summon).

## Development

```bash
export BINARY_NAME="summon-keepass"

go build -ldflags "-s -w" -o $BINARY_NAME
strip $BINARY_NAME
upx -q -9 $BINARY_NAME

sudo cp $BINARY_NAME /usr/local/bin/Providers
```

## Usage

1. create a [secrets.yml](./secrets.yml) configuration file with `secretId`s:

```yaml
# Retrieve the "password" field
# This is equivalent to "path/to/the/secret:Password"
SECRET_VARIABLE: !var path/to/the/secret

# Retrieve other field, e.g.: the "UserName"
USERNAME_VARIABLE: !var path/to/the/secret:UserName
```

2. run `summon`:

```bash
export KEEPASS_FILE_PATH="Database.kdbx"
export KEEPASS_PASSWORD="default123"

summon -p summon-keepass printenv
```
