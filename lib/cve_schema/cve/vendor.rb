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
      # Loads the vendor object from the parsed JSON.
      #
      # @param [Hash{String => Object}] json
      #   The parsed JSON.
      #
      # @return [self]
      #
      def self.from_json(json)
        new(
          vendor_name: json['vendor_name'],
          product:     json['product']['product_data'].map(&Product.method(:from_json))
        )
      end

    end
  end
end
