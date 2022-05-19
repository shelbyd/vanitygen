# vanitygen for Substrate

Generate vanity addresses performantly for Substrate chains. Currently does about 125K keys / s on my mediocre laptop. Should scale linearly with available cores.

## Usage

To generate a private key with a matching public key.

```sh
vanitygen gen --prefix 5F12 --seed-prefix my-company//purpose
```

To generate a public key without the corresponding private key.

```sh
vanitygen create-public --prefix 5FSomethingLong
```

## Limitations

* Currently only for custom chains (with prefix 5)
