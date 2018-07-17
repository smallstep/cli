# Getting Started with Development

To get started with local development, you will need three things:

- Golang installed locally (instructions available [here](https://golang.org/doc/install))
- The repository checked out in the appropriate location of your `$GOPATH`
- A version of `make` available for usage of the `Makefile`

Ensure you've checked out the repository into the appropriate path inside your
`$GOPATH`. For example, if your `$GOPATH` is set to `~/code`, then you'd check
this repository out at `~/code/src/github.com/smallstep/cli`. You can
learn more about `$GOPATH` in the [documentation](https://golang.org/doc/code.html#GOPATH).

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

If you wish to only test or lint you can run `make test` or `make lint`
respectively.

### Adding and Removing Dependencies

To add any dependency to the repository, simply import it into your code and
then run `dep ensure` which will update the `Gopkg.lock` file. A specific
version of a dependency can be specified by adding it to the `Gopkg.toml` file
and running `dep ensure`.

To remove a dependency, simply remove it from the codebase and any mention of
it in the `Gopkg.toml` file and run `dep ensure` which will remove it from the
`vendor` folder while updating the `Gopkg.lock` file.
