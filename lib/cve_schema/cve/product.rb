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
      attr_reader :version

      alias versions version

      #
      # Initializes the product.
      #
      # @param [String] product_name
      #
      # @param [Array<Version>] version
      #
      def initialize(product_name: , version: [])
        @product_name = product_name
        @version      = version
      end

      #
      # Determines if the {#product_name} is `n/a`.
      #
      # @return [Boolean]
      #
      def na?
        @product_name == NA
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
          product_name: json['product_name'],
          version:      Array(json['version']['version_data']).map(&Version.method(:load))
        }
      end

      #
      # Loads the product object from parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Product]
      #   The loaded product.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
