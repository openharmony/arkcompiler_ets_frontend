import re

# Meta
META_START_STRING = "/*---"
META_START_PATTERN = re.compile("\/\*---")
META_END_STRING = "---*/"
META_END_PATTERN = re.compile("---\*\/")

# Extensions
YAML_EXTENSIONS = [".yaml", ".yml"]
TEMPLATE_EXTENSION = ".sts"
OUT_EXTENSION = ".sts"
JAR_EXTENSION = ".jar"

# Prefixes
LIST_PREFIX = "list."
NEGATIVE_PREFIX = "n."
SKIP_PREFIX = "tbd."

# Jinja
VARIABLE_START_STRING = "{{."

# Spec
SPEC_SECTION_TITLE_FIELD_NAME = "name"
SPEC_SUBSECTIONS_FIELD_NAME = "children"