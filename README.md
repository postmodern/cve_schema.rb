# cve_schema

* [Homepage](https://github.com/postmodern/cve_schema#readme)
* [Issues](https://github.com/postmodern/cve_schema/issues)
* [Documentation](http://rubydoc.info/gems/cve_schema/frames)
* [Email](mailto:postmodern.mod3 at gmail.com)

## Description

{CVESchema} provides common classes for CVE data and loading it from JSON.

## Features

* Supports [CVE JSON Schema v4.0][1]

## Examples

    require 'cve_schema'
    include CVESchema

    json = JSON.parse(File.read('path/to/CVE-YYYY-XXXX.json'))
    cve = CVE.from_json(json)

## Requirements

* [ruby] >= 2.7.0

## Install

    $ gem install cve_schema

## Copyright

Copyright (c) 2020-2021 Hal Brodigan

See {file:LICENSE.txt} for details.

[1]: https://github.com/CVEProject/cve-schema/blob/master/schema/v4.0/DRAFT-JSON-file-format-v4.md

[ruby]: https://www.ruby-lang.org/
