#!/usr/bin/env ruby

require 'bundler/setup'
require 'cve_schema/cve'
require 'json'
require 'benchmark'

CVELIST = ENV.fetch('CVELIST',File.join(Gem.user_home,'src','cvelist'))

unless File.directory?(CVELIST)
  $stderr.puts "#{CVELIST} does not exist!"
  $stderr.puts "Please run: git clone https://github.com/CVEProject/cvelist #{CVELIST}"
  exit -1
end

begin
  json_files = Dir.glob(File.join(CVELIST,'**','**','CVE-*.json'))
  n = json_files.length

  puts "Loading all #{n} JSON files into memory. This may take a while ..."

  all_json = {}
  json_files.each do |path|
    all_json[path] = JSON.parse(File.read(path))
  end

  puts "Mapping all #{n} to #{CVESchema::CVE} objects ..."

  results = Benchmark.measure do
    all_json.each do |path,json|
      begin
        CVESchema::CVE.from_json(json)
      rescue CVESchema::InvalidJSON
        # ignore
      rescue => error
        $stderr.puts "error encountered while parsing #{path}"
        raise(error)
      end
    end
  end

  puts
  puts "Total:\t#{results}"
  puts "Avg:\t#{results / n}"
rescue Interrupt
  exit 130
end
