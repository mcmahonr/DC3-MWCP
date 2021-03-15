import re

from mwcp import Parser, FileObject


class Remcos(Parser):
    DESCRIPTION = "Remcos RAT Configuration Parser"

    @classmethod
    def identify(cls, file_object):
        """
        :file_object: The File object to work with
        :type file_object: FileObject
        :return: Boolean value indicating if this file is likely to be Remcos RAT
        """

        # Is an executable file
        decision = file_object.pe and file_object.pe.is_exe()
        if not decision:
            return False

    def run(self):
        version_string = self._get_version_string()
        self.reporter.add_metadata("Version", version_string)

    def _get_version_string(self):
        version_string = "Unknown"
        ascii_strings = self.file_object.stack_strings
        for s in ascii_strings:
            if re.search(b'^[12]\.\d+\d{0,1}.*[FPL].*', s):
                version_string = s
        return version_string
