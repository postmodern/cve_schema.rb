require 'cve_schema/cve/has_lang_value'

module CVESchema
  class CVE
    #
    # Represents a configuration within the `"configuration"` JSON Array.
    #
    class Configuration

      include HasLangValue

    end
  end
end
