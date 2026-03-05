from parsers.base_parser import BaseParser
from utils.exceptions import UnsupportedTemplateFormatError

class TerraformParser(BaseParser):
    """Stub: Terraform HCL parser — future work."""
    def parse(self, path): raise UnsupportedTemplateFormatError("Terraform parsing not yet implemented.")
    def normalize(self, raw): raise UnsupportedTemplateFormatError("Terraform normalization not yet implemented.")
