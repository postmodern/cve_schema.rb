require 'cve_schema/cve/has_lang_value'
require 'cve_schema/cve/na'

module CVESchema
  class CVE
    #
    # Represents a description JSON object.
    #
    class Description

      include HasLangValue

      #
      # Determines if the {#value} is `n/a`.
      #
      # @return [Boolean]
      #
      def na?
        @value == NA
      end

    end
  end
end
