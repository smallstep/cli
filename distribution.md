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

3. Synchronize the versions of `cli` and `certificates`.

    > NOTE: If you do not need to update the version of `certificates` required
    > by the `cli` at this time (and vice versa) then thank your lucky stars and
    > move on to step 5.

    Buckle up and get your affairs in order because here be dragons.

    > NOTE: In the subsequent steps let A.B.C be the new tag for the `cli` repo
    > and X.Y.Z be the new tag for the `certificates repo.

    1. Complete steps 1 & 2 from the [certificates distribution doc][0].

        Up to the part where a tag has been selected, but not applied.

    2. Bump the version of `cli` in the [certificates go.mod][1] to `vA.B.C`.

    3. Commit the change to go.mod. And push the tag.

        ```
        $ git add go.mod; git commit -m "Bump version of cli to vA.B.C"
        $ git tag vX.Y.Z; git tag push
        ```

        This pushed tag will break in Travis because `cli@vA.B.C` does not exist.
        That's okay.

    4. Bump the version of `certificates` in the [cli go.mod][1] to `vX.Y.Z`.

    5. Commit the change to go.mod. And push the tag.

        ```
        $ git add go.mod; git commit -m "Bump version of cli to vX.Y.Z"
        $ git tag vA.B.C; git tag push
        ```

        This tagged build will break in CI/CD because sum.golang.org has not
        yet had the chance to crawl and create an entry for the new tag.

    6. Wait for `https://sum.golang.org/lookup/github.com/smallstep/cli@vA.B.C`
    to be come available.

        Keep looking it up in the browser or pinging it on the command line until
        it becomes available. ~10 - 20 mins.

    7. In [Travis][2] restart the failed, tagged build for `cli` through the UI.

        Now that the `sum.golang.org` entry for `cli` is available the build
        should be able to proceed past downloading the dependencies. Builds of
        `cli` can take up to 15 minutes so sit tight.

    8. In [Travis][3] restart the failed, tagged build for `certificates` through
    the UI.

        Wait till the build of `cli` has completed successfully. The `step-ca`
        dockerfile relies on the `cli:latest` docker build.

    9. Run `go mod tidy` in both `certificates` and `cli` and commit and push
    the changes to `master`.

4. **Tag it!**

    > NOTE: skip this step if you've already tagged and pushed in the previous
    > step.

    3. **Create a local tag.**

        ```
        $ git tag v1.0.3   # standard release
        ...or
        $ git tag v1.0.3-rc.1  # release candidate
        ```

    4. **Push the new tag to the remote origin.**

        ```
        $ git push origin tag v1.0.3   # standard release
        ...or
        $ git push origin tag v1.0.3-rc.1  # release candidate
        ```

    Check the build status at [Travis-CI](https://travis-ci.com/smallstep/cli/builds/).

5. **Update the AUR Arch Linux packages**

    <pre><code>
    ### <b>SETUP</b> ###
    # clone the archlinux repo if you don't already have it.
    <b>$ git clone git@github.com:smallstep/archlinux.git</b>

    ### Get up to date...
    <b>$ cd archlinux && git pull origin master && make</b>

    ### Bump and push new versions

    # If updating the packages for cli and ca
    <b>$ ./update --cli v1.0.3 --ca v1.0.3</b>

    # If only updating the package for cli
    <b>$ ./update --cli v1.0.3</b>
    </code></pre>

    Commit and push the submodule updates to master.

6. **Update the smallstep/smallstep Homebrew tap.**

    > **NOTE**: this only needs to be done for standard releases.

    Follow the steps [here](https://github.com/smallstep/homebrew-smallstep#how-to-update-the-formula).

7. **Update Homebrew Core.**

    > **NOTE**: this only needs to be done for standard releases.

    1. Fork the homebrew-core repo if you don't already have it.

        If you already have the `homebrew-core` repo with `upstream` remote set
        to `homebrew-core` origin:

        ```
        git checkout master
        git fetch --all
        git pull upstream master
        ```

    2. Create a branch in your fork.

        ```
        git checkout -B step-0.10.0</b>
        ```

    3. Apply changes from `smallstep/smallstep/step` tap.

       Take the diff from the `smallstep/homebrew-smallstep` repo and manually
       apply it to your branch. The most common changes should be URL and SHA
       updates.

    4. Test the changes.

       <pre><code>
       # start fresh
       <b>$ brew uninstall step</b>

       # test install
       <b>$ brew install --build-from-source Formula/step.rb</b>

       # setup for audit and test
       <b>$ sudo cp Formula/step.rb /usr/local/Homebrew/Library/Taps/homebrew/homebrew-core/Formula/step.rb</b>

       # audit
       <b>$ brew audit --strict --online step</b>

       # test
       <b>$ brew test step</b>
       </code></pre>


8. **Update the documentation on the website**

    > **NOTE**: this only needs to be done for standard releases.

    Follow the steps [here](https://github.com/smallstep/docs/blob/master/runbook/release.md).

**All Done!**

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/smallstep/cli).
