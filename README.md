# cryptopals

Working through the cryptopals challenges

## Setup

After first cloning the repo, run the following before running cmake to grab all git submodules:

```sh
git submodule update --init --recursive
```

Later, run the following to pull the latest version of each submodule:

```sh
git submodule update --remote --recursive
```

- Todo: Package up utils so that it works with cmake properly