## Getting Started with Development

These instructions will get you a copy of the project up and running on your
local machine for development, testing, and contribution purposes.

Please read the [CLI Style Guide](https://github.com/urfave/cli) before
implementing any features or modifying behavior as it contains expectations
surrounding how the CLI should behave.

All changes to behavior *must* be documented in the [CHANGELOG.md](../CHANGELOG.md).

### Prerequisites

To get started with local development, you will need three things:

- Golang installed locally (instructions available
[here](https://golang.org/doc/install)).
- dep installed locally (instructions available
[here](https://golang.github.io/dep/docs/installation.html)).
- A version of `make` available for usage of the `Makefile`.
- The repository checked out in the appropriate location of your `$GOPATH`.

Ensure you've checked out the repository into the appropriate path inside your
`$GOPATH`. For example, if your `$GOPATH` is set to `~/go`, then you'd check
this repository out at `~/go/src/github.com/smallstep/cli`. You can
learn more about `$GOPATH` in the
[documentation](https://golang.org/doc/code.html#GOPATH).

### Installing Dependencies and Bootstrapping

Once you've cloned the repository to the appropriate location, you will now be
able to install any other dependencies via the `make bootstrap` command.

You should only ever need to run this command once, as it will ensure you have
the right version of `dep` and `gometalinter` installed.

### Building step

To build step, simply run `make build` which will build the cli and place the
binary in the `bin` folder.

### Running Tests and Linting

Now that you've installed any dependencies, you can run the tests and lint the
code base simply by running `make`.

#### Unit Tests

Run the unit tests:

```
make test
```

For a more verbose version of the unit tests:

```
make vtest
```

#### Integration Tests

Run the integration tests:

```
make integration
```

#### And coding style tests

These tests apply the following `Go` linters to verify code style and formatting:

* [deadcode](https://github.com/tsenart/deadcode)
* [gofmt](https://golang.org/cmd/gofmt/)
* [golint](https://github.com/golang/lint/golint)
* [ineffassign](https://github.com/gordonklaus/ineffassign)
* [metalinter](https://github.com/alecthomas/gometalinter)
* [misspell](https://github.com/client9/misspell/cmd/misspell)
* [vet](https://golang.org/cmd/vet/)

```
make lint
```

### Adding and Removing Dependencies

To add any dependency to the repository, simply import it into your code and
then run `dep ensure` which will update the `Gopkg.lock` file. A specific
version of a dependency can be specified by adding it to the `Gopkg.toml` file
and running `dep ensure`.

To remove a dependency, simply remove it from the codebase and any mention of
it in the `Gopkg.toml` file and run `dep ensure` which will remove it from the
`vendor` folder while updating the `Gopkg.lock` file.
