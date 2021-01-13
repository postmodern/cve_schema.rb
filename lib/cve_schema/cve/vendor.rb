require 'cve_schema/cve/product'
require 'cve_schema/cve/na'

module CVESchema
  class CVE
    #
    # Represents an element within the `"vendor_data"` JSON Array.
    #
    class Vendor

      # @return [String]
      attr_reader :vendor_name

      # @return [Array<Product>]
      attr_reader :product

      #
      # Initializes the vendor object.
      #
      # @param [String] vendor_name
      #
      # @param [Array<Product>] product
      #
      def initialize(vendor_name: , product: )
        @vendor_name = vendor_name
        @product     = product
      end

      #
      # Determines if the {#vendor_name} is `n/a`.
      #
      # @return [Boolean]
      #
      def na?
        @vendor_name == NA
      end

      #
      # Converts the vendor object to a String.
      #
      # @return [String]
      #   The vendor name
      #
      def to_s
        @vendor_name
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
          vendor_name: json['vendor_name'],
          product:     json['product']['product_data'].map(&Product.method(:load))
        }
      end

      #
      # Loads the vendor object from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [Vendor]
      #   The loaded vendor object.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

    end
  end
end
