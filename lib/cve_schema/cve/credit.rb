require 'cve_schema/cve/has_lang_value'

module CVESchema
  class CVE
    #
    # Represents a credit within the `"credit"` JSON Array.
    #
    class Credit

      include HasLangValue

    end
  end
end
