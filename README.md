# cve_schema

[![CI](https://github.com/postmodern/cve_schema.rb/actions/workflows/ruby.yml/badge.svg)](https://github.com/postmodern/cve_schema.rb/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/postmodern/cve_schema.rb.svg)](https://codeclimate.com/github/postmodern/cve_schema.rb)

* [Homepage](https://github.com/postmodern/cve_schema.rb#readme)
* [Issues](https://github.com/postmodern/cve_schema.rb/issues)
* [Documentation](http://rubydoc.info/gems/cve_schema/frames)
* [Email](mailto:postmodern.mod3 at gmail.com)

## Description

{CVESchema} provides common classes for CVE data and loading it from JSON.

## Features

* Supports [CVE JSON Schema v4.0].
* Uses Plain-Old-Ruby-Objects (PORO) for speed!
* No runtime dependencies.

## Examples

```ruby
require 'cve_schema'
include CVESchema

json = JSON.parse(File.read('path/to/CVE-YYYY-XXXX.json'))
cve = CVE.load(json)
```

## Requirements

* [ruby] >= 2.7.0

## Install

```shell
$ gem install cve_schema
```

### Gemfile

```ruby
gem 'cve_schema', '~> 0.1'
```

## Benchmark

    Loading all 192879 JSON files into memory. This may take a while ...
    Mapping all 192879 to CVESchema::CVE objects ...
    
    Total:	 12.310090   0.275629  12.585719 ( 12.664896)
    Avg:	  0.000064   0.000001   0.000065 (  0.000066)

## Copyright

Copyright (c) 2020-2021 Hal Brodigan

See {file:LICENSE.txt} for details.

[CVE JSON Schema v4.0]: https://github.com/CVEProject/cve-schema/blob/master/schema/v4.0/DRAFT-JSON-file-format-v4.md

[ruby]: https://www.ruby-lang.org/
