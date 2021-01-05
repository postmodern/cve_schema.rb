require 'cve_schema/cve/na'

module CVESchema
  class CVE
    #
    # Represents an element within the `"version_data"` JSON Array.
    #
    class Version

      # @return [String]
      attr_reader :value_value

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
      # Loads the version object from parsed JSON.
      #
      # @param [Hash{String => String}] json
      #
      # @return [Version]
      #
      def self.from_json(json)
        new(
          version_affected: json['version_affected'] &&
                              VERSION_AFFECTED.fetch(json['version_affected']),
          version_name:     json['version_name'],
          version_value:    json['version_value']
        )
      end

      def na?
        @version_value == NA
      end

      #
      # Converts the version into a String.
      #
      # @param [String]
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
