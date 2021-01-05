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
    def initialize(data_type: , data_format: , data_version: ,
                   data_meta: nil,
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
                   work_around: []
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
    end

    #
    # Loads the CVE data from parsed JSON.
    #
    # @param [Hash{String => Object}] json
    #   The parsed JSON.
    #
    # @return [self]
    #
    def self.from_json(json)
      new(
        data_type:    DATA_TYPES.fetch(json['data_type']),
        data_format:  DATA_FORMAT.fetch(json['data_format']),
        data_version: DATA_VERSIONS.fetch(json['data_version']),

        data_meta: DataMeta.from_json(json['CVE_data_meta']),

        affects:   json['affects'] && Affects.from_json(json['affects']),
        configuration: Array(json['configuration']).map(&Configuration.method(:from_json)),
        problemtype: Array(json['problemtype'] && json['problemtype']['problemtype_data']).map(&ProblemType.method(:from_json)),

        references: Array(json['references'] && json['references']['reference_data']).map(&Reference.method(:from_json)),

        description: Array(json['description'] && json['description']['description_data']).map(&Description.method(:from_json)),

        exploit: Array(json['exploit']).map(&Exploit.method(:from_json)),
        credit: Array(json['credit']).map(&Credit.method(:from_json)),
        impact: json['impact'] && Impact.from_json(json['impact']),
        solution: Array(json['solution']).map(&Solution.method(:from_json)),
        source: json['source'] && Source.from_json(json['source']),
        work_around: Array(json['work_around']).map(&WorkAround.method(:from_json))
      )
    end

  end
end
