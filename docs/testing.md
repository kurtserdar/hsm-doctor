# Testing

HSM Doctor has two test layers:

## Unit tests

Pure-logic tests (policy engine, drift detection, reporters, parsers) that
need no HSM at all:

```sh
make test
```

## Integration tests

End-to-end tests that exercise the PKCS#11 code paths against a real token.
They use [SoftHSM2](https://github.com/softhsm/SoftHSMv2) and are guarded by
the `integration` build tag:

```sh
sudo apt-get install softhsm2   # Debian/Ubuntu
make integration
```

Each test initializes a throwaway token in a temporary directory (via a
private `SOFTHSM2_CONF`), so runs never touch your real SoftHSM token store
and need no root privileges.

If your SoftHSM library lives in a non-standard location, point the tests at
it explicitly:

```sh
HSMDOCTOR_TEST_MODULE=/path/to/libsofthsm2.so make integration
```

Both layers run on every push and pull request via GitHub Actions
(`.github/workflows/ci.yml`).
