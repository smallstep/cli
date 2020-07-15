# Distribution

This section describes how to build and deploy publicly available releases of
the Step CLI.

## Creating A New Release

New releases are (almost) entirely built and deployed by Travis-CI. Creating a new
release is as simple as pushing a new github tag.

**Definitions**:

* **Standard Release**: ready for public use. no `-rc*` suffix on the version.
e.g. `v1.0.2`
* **Release Candidate**: not ready for public use, still testing. must have a
`-rc*` suffix. e.g. `v1.0.2-rc` or `v1.0.2-rc.4`

1. **Update smallstep/certificates.**

    ```
    $ go get -u github.com/smallstep/certificates
    ```

1. **Commit all changes.**

    Make sure that the local checkout is up to date with the remote origin and
    that all local changes have been pushed.

    ```
    $ git pull --rebase origin master
    $ git push
    ```

2. **Select the value of the next tag, but DON'T tag it!**

    1. **Find the most recent tag.**

        ```
        $ git fetch --tags
        $ git tag
        ```

        The new tag needs to be the logical successor of the most recent existing tag.
        See [versioning](#versioning) section for more information on version numbers.

    2. **Select the type and value of the next tag.**

        Is the new release a *release candidate* or a *standard release*?

        1. Release Candidate

            If the most recent tag is a standard release, say `v1.0.2`, then the version
            of the next release candidate should be `v1.0.3-rc.1`. If the most recent tag
            is a release candidate, say `v1.0.2-rc.3`, then the version of the next
            release candidate should be `v1.0.2-rc.4`.

        2. Standard Release

            If the most recent tag is a standard release, say `v1.0.2`, then the version
            of the next standard release should be `v1.0.3`. If the most recent tag
            is a release candidate, say `v1.0.2-rc.3`, then the version of the next
            standard release should be `v1.0.3`.

3. **Synchronize the versions of `cli` and `certificates`.**

    > **NOTE**: If you do not need to update the version of `certificates` required
    > by the `cli` at this time (and vice versa) then thank your lucky stars and
    > move on to step 5.

    Buckle up and get your affairs in order because here be dragons.

    > NOTE: In the subsequent steps let A.B.C be the new tag for the `cli` repo
    > and X.Y.Z be the new tag for the `certificates` repo.

    1. Complete steps 1 & 2 from the [`certificates` distribution doc][1].

        Up to the part where a tag has been selected, but not applied.

    2. Bump the version of `cli` in the [`certificates` go.mod][2] to `vA.B.C`.

    3. Commit the change to go.mod. And push the tag.

        ```
        $ git add go.mod; git commit -m "Bump version of cli to vA.B.C"
        $ git tag vX.Y.Z; git tag push
        ```

        This pushed tag will break in Travis because `cli@vA.B.C` does not exist.
        That's okay.

    4. Bump the version of `certificates` in the [`cli` go.mod][3] to `vX.Y.Z`.

    5. Commit the change to go.mod. And push the tag.

        ```
        $ git add go.mod; git commit -m "Bump version of cli to vX.Y.Z"
        $ git tag vA.B.C; git tag push
        ```

        This tagged build will break in CI/CD because sum.golang.org has not
        yet had the chance to crawl and create an entry for the new tag.

    6. Wait for `https://sum.golang.org/lookup/github.com/smallstep/cli@vA.B.C`
    to become available.

        Keep looking it up in the browser or `curl`ing it from the command line
        until it becomes available. ~10 - 20 mins.

    7. In [Travis][4] restart the failed, tagged build for `cli` through the UI.

        Now that the `sum.golang.org` entry for `cli` is available the build
        should be able to proceed past downloading the dependencies. Builds of
        `cli` can take up to 15 minutes so sit tight.

    8. In [Travis][5] restart the failed, tagged build for `certificates` through
    the UI.

        Wait till the build of `cli` has completed successfully. The `step-ca`
        dockerfile relies on the `cli:latest` docker build.

    9. Run `go mod tidy` in both `certificates` and `cli` and commit and push
    the changes to `master`.

4. **Tag it!**

    > **NOTE**: Skip this step if you've already tagged and pushed in the previous
    > step.

    1. **Create a local tag.**

        ```
        $ git tag v1.0.3   # standard release
        ...or
        $ git tag v1.0.3-rc.1  # release candidate
        ```

    2. **Push the new tag to the remote origin.**

        ```
        $ git push origin tag v1.0.3   # standard release
        ...or
        $ git push origin tag v1.0.3-rc.1  # release candidate
        ```

    Check the build status at [Travis-CI](https://travis-ci.com/smallstep/cli/builds/).

**All Done!**

[1]: https://github.com/smallstep/certificates/blob/master/distribution.md
[2]: https://github.com/smallstep/certificates/blob/master/go.mod
[3]: https://github.com/smallstep/cli/blob/master/go.mod
[4]: https://travis-ci.com/smallstep/cli/builds/
[5]: https://travis-ci.com/smallstep/certificates/builds/

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/smallstep/cli).
