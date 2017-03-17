
## Development zen

This starter includes a watch task which makes development faster and more interactive. It's particularly helpful for [TDD](https://en.wikipedia.org/wiki/Test-driven_development)/[BDD](https://en.wikipedia.org/wiki/Behavior-driven_development) workflows.

To start working, [install Yarn](https://yarnpkg.com/en/docs/getting-started) and run:

```
yarn watch
```

## View test coverage

To generate and view test coverage, run:
```bash
yarn cov
```

This will create an HTML report of test coverage – source-mapped back to Typescript – and open it in your default browser.

<p align="center">
  <img height="600" alt="source-mapped typescript test coverage example" src="https://cloud.githubusercontent.com/assets/904007/22909301/5164c83a-f221-11e6-9d7c-72c924fde450.png">
</p>

## Generate your API docs

The src folder is analyzed and documentation is automatically generated using [typedoc](https://github.com/TypeStrong/typedoc).

```bash
yarn docs
```
This command generates API documentation for your library in HTML format.

Since types are tracked by Typescript, there's no need to indicate types in JSDoc format. For more information, see the [typedoc documentation](http://typedoc.org/guides/doccomments/).

<p align="center">
  <img height="500" alt="typedoc documentation example" src="https://cloud.githubusercontent.com/assets/904007/22909419/085b9e38-f222-11e6-996e-c7a86390478c.png">
</p>

For more advanced documentation generation, you can provide your own [typedoc theme](http://typedoc.org/guides/themes/), or [build your own documentation](https://blog.cloudflare.com/generating-documentation-for-typescript-projects/) using the JSON typedoc export:

```bash
yarn docs:json
```

## Generate/update changelog & release

This project is tooled for [Conventional Changelog](https://github.com/conventional-changelog/conventional-changelog) to make managing releases easier. See the [standard-version](https://github.com/conventional-changelog/standard-version) documentation for more information on the workflow, or [`CHANGELOG.md`](CHANGELOG.md) for an example.

```bash
# bump package.json version, update CHANGELOG.md, git tag the release
yarn release
# Release without bumping package.json version
yarn release -- --first-release
# PGP sign the release
yarn release -- --sign
```

## All package scripts

You can run the `info` script for information on each available package script.

```
yarn run info

  info:
    Display information about the scripts
  build:
    (Trash and re)build the library
  lint:
    Lint all typescript source files
  unit:
    Run unit tests
  test:
    Lint and test the library
  watch:
    Watch source files, rebuild library on changes, rerun relevant tests
  watch:build:
    Watch source files, rebuild library on changes
  watch:unit:
    Watch the build, rerun relevant tests on changes
  cov:
    Run tests, generate the HTML coverage report, and open it in a browser
  html-coverage:
    Output HTML test coverage report
  send-coverage:
    Output lcov test coverage report and send it to codecov
  docs:
    Generate API documentation and open it in a browser
  docs:json:
    Generate API documentation in typedoc JSON format
  release:
    Bump package.json version, update CHANGELOG.md, tag a release
```


Based on https://github.com/bitjson/typescript-starter
