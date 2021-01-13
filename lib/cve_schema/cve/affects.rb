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
      # Maps the parsed JSON to an Array of {Vendor} objects for {#initialize}.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Array<Vendor>]
      #
      def self.from_json(json)
        json['vendor']['vendor_data'].map(&Vendor.method(:load))
      end

      #
      # Loads the affects object from parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Affects]
      #   The loaded affects object.
      #
      def self.load(json)
        new(from_json(json))
      end

    end
  end
end
