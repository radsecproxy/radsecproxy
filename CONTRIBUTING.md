# Contributing to radsecproxy

We are happy that you want to help.
Please read this document before starting your contribution to radsecproxy.

## Code Style

We use [clang-format](https://clang.llvm.org/docs/ClangFormat.html) to autoformat the code.
Please use this code style in all your contributions.

Many IDEs already support clang-format and will detect its configuration `.clang-format` automatically.

We also provide an example script to reformat all code in `tools/clang-format.hook`. It can either be run standalone or as a pre-commit hook in git.

## Git workflow

If you want to contribute to radsecproxy, please base your contributions on the current `master` and rebase your changes regularly to the new `master`, after you submitted your pull request.

## Unit Tests

Writing unit tests for non-trivial functions is appreciated, see `tests/` directory.
Before submitting a pull request, please make sure all unit tests still pass.

## OpenSSL Library Backwards compatibility

To ensure a broad compatibility with many different systems, the code should be written with different OpenSSL Library versions in mind.

The oldest and newest supported OpenSSL library version should be the version currently shipped in the oldest and newest maintained OS versions of Debian and Ubuntu.

As of 2023-08-10:
| OS Version | OpenSSL version |
|------------|-----------------|
| Debian 10 (Buster) | 1.1.1n |
| Debian 11 (Bullseye) | 1.1.1n |
| Debian 12 (Bookworm) | **3.0.9** |
| Ubuntu 20.04 LTS (Focal Fossa) | **1.1.1f** |
| Ubuntu 22.04 LTS (Jammy Jellyfish) | 3.0.2 |
| Ubuntu 22.10 (Kinetic Kudu) | 3.0.5 |
| Ubuntu 23.04 (Lunar Lobster) | 3.0.8 |

If there were changes in the OpenSSL API, please include pre-processor clauses depending on the OpenSSL Version number

```c
#if OPENSSL_VERSION_NUMBER < 0x101010efL
  // code for OpenSSL before 1.1.1n
#else
  // code for OpenSSL after (including) 1.1.1n
#endif
```

Note that radsecproxy currently maintains compatibility with much older versions of OpenSSL,
however this will be removed at some point. New features are not required to support these
older versions, but should include a featrue gate (see above), if a certain minimum version
is required. 

## Ignore code style commits in git blame

Since the code style was introduced between Radsecproxy 1.10 and 1.11, there were significant changes in the code that were solely code styles.
These changes were made in one commit. This commit is now shown as change commit in commands like `git blame`.

All commits that are only code style commits are included in the file `.git-blame-ignore-revs`.

Github will automatically exclude these commits from the history view.
To hide these commits from the local history in `git blame` too, you can simply run the following command:
```
git config blame.ignoreRevsFile .git-blame-ignore-revs
```

