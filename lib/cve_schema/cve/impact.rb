require 'cve_schema/cve/impact/cvss_v2'
require 'cve_schema/cve/impact/cvss_v3'

module CVESchema
  class CVE
    class Impact

      # @return [CVSSv2, nil]
      attr_reader :cvssv2

      alias cvss_v2 cvssv2

      # @return [CVSSv3, nil]
      attr_reader :cvssv3

      alias cvss_v3 cvssv3

      #
      # Initializes the impact object.
      #
      # @param [CVSSv2, nil] cvssv2
      #   The CVSSv2 object.
      #
      # @param [CVSSv3, nil] cvssv3
      #   The CVSSv3 object.
      #
      def initialize(cvssv2: nil, cvssv3: nil)
        @cvssv2 = cvssv2
        @cvssv3 = cvssv3
      end

      #
      # Maps the parsed JSON to a Symbol Hash for {#initialize}.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Hash{Symbol => Object}]
      #   The mapped Symbol Hash.
      #
      # @api semipublic
      #
      def self.from_json(json)
        {
          cvssv2: json['cvssv2'] && CVSSv2.load(json['cvssv2']),
          cvssv3: json['cvssv3'] && CVSSv3.load(json['cvssv3'])
        }
      end

      #
      # Loads the impact object from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Impact]
      #   The loaded impact object.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
