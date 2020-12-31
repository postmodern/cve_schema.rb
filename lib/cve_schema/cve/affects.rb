require 'cve_schema/cve/vendor'

module CVESchema
  class CVE
    #
    # Represents the `"affects"` JSON object.
    #
    class Affects

      # @return [Array<Vendor>]
      attr_reader :vendor

      alias vendors vendor

      #
      # Initializes the affects container.
      #
      # @param [Array<Vendor>] vendor
      #
      def initialize(vendor)
        @vendor = vendor
      end

      #
      # Loads the affects object from parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #
      def self.from_json(json)
        new(
          json['vendor']['vendor_data'].map(&Vendor.method(:from_json))
        )
      end

    end
  end
end
