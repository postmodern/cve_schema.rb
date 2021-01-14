# frozen_string_literal: true

require 'cve_schema/exceptions'
require 'cve_schema/cve/na'

module CVESchema
  class CVE
    #
    # Represents an element within the `"version_data"` JSON Array.
    #
    class Version

      # @return [String]
      attr_reader :version_value

      VERSION_AFFECTED = {
        '='   => :"=",  # affects version_value
        '<'   => :"<",  # affects versions prior to version_value
        '>'   => :">",  # affects versions later than version_value
        '<='  => :"<=", # affects version_value and prior versions
        '>='  => :">=", # affects version_value and later versions
        '!'   => :"!",  # doesn't affect version_value
        '!<'  => :"!<", # doesn't affect versions prior to version_value
        '!>'  => :"!>", # doesn't affect versions later than version_value
        '!<=' => :"!<=",# doesn't affect version_value and prior versions
        '!>=' => :"!>=",# doesn't affect version_value and later versions
        '?'   => :"?",  # status of version_value is unknown
        '?<'  => :"?<", # status of versions prior to version_value is unknown
        '?>'  => :"?>", # status of versions later than version_value is unknown
        '?<=' => :"?<=",# status of version_value and prior versions is unknown
        '?>=' => :"?>=",# status of version_value and later versions is unknown
      }

      # @return [nil, :'=', :'<', :'>', :'<=', , :'>=', :'!', :'!<', :'!>', :'!<=', :'!>=', :'?', :'?<', :'?>', :'?<=', :'?>=']
      attr_reader :version_affected

      # @return [nil, String]
      attr_reader :version_name

      #
      # Initializes the version.
      #
      # @param [String] version_value
      #
      # @param [String, nil] version_name
      #
      # @param [nil, :'=', :'<', :'>', :'<=', , :'>=', :'!', :'!<', :'!>', :'!<=', :'!>=', :'?', :'?<', :'?>', :'?<=', :'?>='] version_affected
      #   The version comparison operator. See {VERSION_AFFECTED}.
      #
      def initialize(version_value: , version_name: nil, version_affected: nil)
        @version_value    = version_value
        @version_name     = version_name
        @version_affected = version_affected
      end

      #
      # Maps the parsed JSON to a Symbol Hash for {#initialize}.
      #
      # @param [Hash{String => String}] json
      #   The parsed JSON.
      #
      # @return [Hash{Symbol => Object}]
      #   The mapped Symbol Hash.
      #
      # @raise [UnknownJSONValue]
      #   The `"version_affected"` JSON value was unknown.
      #
      # @api semipublic
      #
      def self.from_json(json)
        {
          version_affected: if (version_affected = json['version_affected'])
                              VERSION_AFFECTED.fetch(version_affected) do
                                raise(UnknownJSONValue,'version_affected',version_affected)
                              end
                            end,

          version_name:     json['version_name'],
          version_value:    json['version_value']
        }
      end

      #
      # Loads the version object from parsed JSON.
      #
      # @param [Hash{String => String}] json
      #   The parsed JSON.
      #
      # @return [Version]
      #   The loaded version object.
      #
      # @raise [UnknownJSONValue]
      #   The `"version_affected"` JSON value was unknown.
      #
      # @api semipublic
      #
      def self.load(json)
        new(**from_json(json))
      end

      #
      # Determines if the {#version_value} is `n/a`.
      #
      # @return [Boolean]
      #
      def na?
        @version_value == NA
      end

      #
      # Converts the version into a String.
      #
      # @return [String]
      #   The {#version_value} and additionally the {#version_affected}.
      #
      def to_s
        if @version_affected
          "#{@version_affected} #{@version_value}"
        else
          @version_value
        end
      end

    end
  end
end
