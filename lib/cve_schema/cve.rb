# frozen_string_literal: true

require 'cve_schema/exceptions'
require 'cve_schema/cve/data_meta'
require 'cve_schema/cve/affects'
require 'cve_schema/cve/configuration'
require 'cve_schema/cve/problem_type'
require 'cve_schema/cve/reference'
require 'cve_schema/cve/description'
require 'cve_schema/cve/exploit'
require 'cve_schema/cve/credit'
require 'cve_schema/cve/impact'
require 'cve_schema/cve/solution'
require 'cve_schema/cve/source'
require 'cve_schema/cve/work_around'
require 'cve_schema/cve/timeline'

module CVESchema
  #
  # Represents a `"cve"` JSON object.
  #
  class CVE

    DATA_TYPES = {
      'CVE' => :CVE,
      'CNA' => :CNA,
      'CVEMENTOR' => :CVEMENTOR
    }

    # @return [:CVE, :CNA, :CVEMENTOR]
    attr_reader :data_type

    DATA_FORMAT = {
      'MITRE' => :MITRE
    }

    # @return [:MITRE]
    attr_reader :data_format

    DATA_VERSIONS = {
      '4.0' => :"4.0"
    }

    # @return [:"4.0"]
    attr_reader :data_version

    # @return [DataMeta]
    attr_reader :data_meta

    alias metadata data_meta

    # @return [Affects, nil]
    attr_reader :affects

    # @return [Array<Configuration>]
    attr_reader :configuration

    alias configurations configuration

    # @return [ProblemType]
    attr_reader :problemtype

    alias problem_type problemtype
    alias problem_types problemtype

    # @return [Array<Reference>]
    attr_reader :references

    # @return [Array<Description>]
    attr_reader :description

    alias descriptions description

    # @return [Array<Exploit>]
    attr_reader :exploit

    alias exploits exploit

    # @return [Array<Credit>]
    attr_reader :credit

    alias credits credit

    # @return [Impact, nil]
    attr_reader :impact

    # @return [Array<Solution>]
    attr_reader :solution

    alias solutions solution

    # @return [Source, nil]
    attr_reader :source

    # @return [Array<WorkAround>]
    attr_reader :work_around

    alias work_arounds work_around

    # @return [Array<Timeline>]
    attr_reader :timeline

    #
    # Initializes the CVE.
    #
    # @param [:CVE, :CNA, :CVEMENTOR] data_type
    #
    # @param [:MITRE] data_format
    #
    # @param [:"4.0"] data_version
    #
    # @param [DataMeta] data_meta
    #
    # @param [Affects, nil] affects
    #
    # @param [Array<Configuration>] configuration
    #
    # @param [ArrayProblemType>] problemtype
    #
    # @param [Array<Reference>] references
    #
    # @param [Array<Description>] description
    #
    # @param [Array<Exploit>] exploit
    #
    # @param [Array<Credit>] credit
    #
    # @param [Array<Impact>] impact
    #
    # @param [Array<Solution>] solution
    #
    # @param [Source, nil] source
    #
    # @param [Array<WorkAround>] work_around
    #
    # @param [Array<Timeline>] timeline
    #
    # @api semipublic
    #
    def initialize(data_type: , data_format: , data_version: , data_meta: ,
                   affects: nil,
                   configuration: [],
                   problemtype: [],
                   references: [],
                   description: [],
                   exploit: [],
                   credit: [],
                   impact: nil,
                   solution: [],
                   source: nil,
                   work_around: [],
                   timeline: []
                  )
      @data_type    = data_type
      @data_format  = data_format
      @data_version = data_version

      @data_meta = data_meta
      @affects   = affects
      @configuration = configuration
      @problemtype = problemtype
      @references = references
      @description = description
      @exploit = exploit
      @credit = credit
      @impact = impact
      @solution = solution
      @source = source
      @work_around = work_around
      @timeline = timeline
    end

    #
    # Maps the JSON Hash into a Symbols Hash for {#initialize}.
    #
    # @param [Hash{String => Object}] json
    #   The parsed JSON.
    #
    # @return [Hash{Symbol => Object}]
    #   The mapped Symbol Hash.
    #   
    # @raise [MissingJSONKey]
    #   The `"data_type"`, `"data_format"`, `"data_version"`, or
    #   `"CVE_data_key"` JSON keys were missing.
    #
    # @api semipublic
    #
    def self.from_json(json)
      {
        data_type:    if (data_type = json['data_type'])
                        DATA_TYPES.fetch(data_type) do
                          raise UnknownJSONValue.new('data_type',data_type)
                        end
                      else
                        raise MissingJSONKey.new('data_type')
                      end,

        data_format:  if (data_format = json['data_format'])
                        DATA_FORMAT.fetch(data_format) do
                          raise UnknownJSONValue.new('data_format',data_format)
                        end
                      else
                        raise MissingJSONKey.new('data_format')
                      end,

        data_version: if (data_version = json['data_version'])
                        DATA_VERSIONS.fetch(data_version) do
                          raise UnknownJSONValue.new('data_version',data_version)
                        end
                      else
                        raise MissingJSONKey.new('data_version')
                      end,

        data_meta: if (cve_data_meta = json['CVE_data_meta'])
                     DataMeta.load(cve_data_meta)
                   else
                     raise MissingJSONKey.new('CVE_data_meta')
                   end,

        affects:   json['affects'] && Affects.load(json['affects']),
        configuration: Array(json['configuration']).map(&Configuration.method(:load)),
        problemtype: Array(json['problemtype'] && json['problemtype']['problemtype_data']).map(&ProblemType.method(:load)),

        references: Array(json['references'] && json['references']['reference_data']).map(&Reference.method(:load)),

        description: Array(json['description'] && json['description']['description_data']).map(&Description.method(:load)),

        exploit: Array(json['exploit']).map(&Exploit.method(:load)),
        credit: Array(json['credit']).map(&Credit.method(:load)),
        impact: json['impact'] && Impact.load(json['impact']),
        solution: Array(json['solution']).map(&Solution.method(:load)),
        source: json['source'] && Source.load(json['source']),
        work_around: Array(json['work_around']).map(&WorkAround.method(:load)),
        timeline: Array(json['timeline']).map(&Timeline.method(:load))
      }
    end

    #
    # Loads the CVE data from parsed JSON.
    #
    # @param [Hash{String => Object}] json
    #   The parsed JSON.
    #
    # @return [self]
    #
    # @raise [MissingJSONKey]
    #   The `"data_type"`, `"data_format"`, `"data_version"`, or
    #   `"CVE_data_key"` JSON keys were missing.
    #
    # @api public
    #
    def self.load(json)
      new(**from_json(json))
    end

  end
end
