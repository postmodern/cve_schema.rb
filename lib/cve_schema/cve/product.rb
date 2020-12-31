require 'cve_schema/cve/version'
require 'cve_schema/cve/na'

module CVESchema
  class CVE
    #
    # Represents a product element within the `"product_data"` JSON Array.
    #
    class Product

      # The product name.
      #
      # @return [String]
      attr_reader :product_name

      # The list of affected versions.
      #
      # @return [Array<Version>]
      attr_reader :versions

      #
      # Initializes the product.
      #
      # @param [String] product_name
      #
      # @param [Array<Version>] versions
      #
      def initialize(product_name: , versions: [])
        @product_name = product_name
        @versions     = versions
      end

      def na?
        @product_name == NA
      end

      #
      # Loads the product object from parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #
      def self.from_json(json)
        new(
          product_name: json['product_name'],
          versions:     Array(json['versions']).map(&Version.method(:from_json))
        )
      end

    end
  end
end
