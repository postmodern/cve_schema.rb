require 'cve_schema/cve/has_lang_value'

module CVESchema
  class CVE
    #
    # Represents an entry within the `"work_around"` JSON Array.
    #
    class WorkAround

      include HasLangValue

    end
  end
end
