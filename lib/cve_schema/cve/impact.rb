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

      def initialize(cvssv2: nil, cvssv3: nil)
        @cvssv2 = cvssv2
        @cvssv3 = cvssv3
      end

      #
      # @param [Hash{String => Object}] json
      #
      # @return [Impact]
      #
      def self.from_json(json)
        new(
          cvssv2: json['cvssv2'] && CVSSv2.from_json(json['cvssv2']),
          cvssv3: json['cvssv3'] && CVSSv3.from_json(json['cvssv3'])
        )
      end

    end
  end
end
