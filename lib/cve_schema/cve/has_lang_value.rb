module CVESchema
  class CVE
    #
    # Mixins for JSON objects containing `"lang"` and `"value"` keys.
    #
    module HasLangValue

      #
      # Adds {ClassMethods} to the class.
      #
      # @param [Class] base
      #   The class including {HasLangValue}.
      #
      def self.included(base)
        base.extend ClassMethods
      end

      #
      # Class methods.
      #
      module ClassMethods
        LANG = {
          'en' => :en, # English
          'es' => :es, # Spanish
        }

        #
        # Loads the objects from the parsed JSON.
        #
        # @param [Hash{String => Object}] json
        #   The parsed JSON.
        #
        # @return [HasLangValue]
        #
        def from_json(json)
          new(
            lang:  LANG.fetch(json['lang'],json['lang']),
            value: json['value']
          )
        end
      end

      # Language identifier for {#value}.
      #
      # @return [:en, :es, String]
      attr_reader :lang

      # Text value.
      #
      # @return [String]
      attr_reader :value

      #
      # Initializes {#lang} and {#value}.
      #
      # @param [:en, :es, String] lang
      #
      # @param [String] value
      #
      def initialize(lang: , value: )
        @lang  = lang
        @value = value
      end

      #
      # Converts the object to a String.
      #
      # @return [String]
      #   Returns the {#value}.
      #
      def to_s
        @value
      end

    end
  end
end
