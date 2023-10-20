import json
from datetime import datetime
from copy import deepcopy
from dojo.tools.sysdig.sysdig_data import SysdigData

class JSONParser:
    """
    Sysdig JSON Data Parser
    """
    def _safe_get(self, structure, *keys):
        for key in keys:
            if isinstance(structure, dict) and key in structure:
                structure = structure.get(key)
                if structure is None: 
                    return ""
            elif isinstance(structure, list) and isinstance(key, int) and 0 <= key < len(structure):
                structure = structure[key]
                if structure is None:
                    return ""
            else:
                return ""
        return structure

    def _map_severity(self, severity):
        severity_mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "NEGLIGIBLE": "Informational"
        }
    
        return severity_mapping.get(severity, "Informational")

    def parse(self, filename) -> SysdigData:

        if filename is None:
            return ()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        
        json_data = json.loads(content)
        json_packages = json_data['packages']['list']
        json_vuln_list = json_data['vulnerabilities']['list']
        json_metadata = json_data['metadata']

        arr_json_data = []

        for row_vuln in json_vuln_list:
            json_data_record = SysdigData()

            json_data_record.vulnerability_id = self._safe_get(row_vuln,'name')
            
            json_data_record.severity = self._map_severity(self._safe_get(row_vuln,'severity','label').upper())
            json_data_record.vuln_link = self._safe_get(row_vuln,'cvssScore','sourceUrl')
            json_data_record.url = json_data_record.vuln_link
            json_data_record.public_exploit = self._safe_get(row_vuln,'exploit')
            json_data_record.cvss_score = self._safe_get(row_vuln,'cvssScore','value','score')
            json_data_record.cvss_vector = self._safe_get(row_vuln,'cvssScore','value','vector')
            json_data_record.cvss_version = self._safe_get(row_vuln,'cvssScore','value','version')

            json_data_record.vuln_fix_date = self._safe_get(row_vuln,'solutionDate')            
            if json_data_record.vuln_fix_date != "":
                json_data_record.vuln_fix_date = datetime.fromisoformat(json_data_record.vuln_fix_date.replace("Z", "+00:00"))

            json_data_record.vuln_publish_date = self._safe_get(row_vuln,'disclosureDate')
            if json_data_record.vuln_publish_date != "":
                json_data_record.vuln_publish_date = datetime.fromisoformat(json_data_record.vuln_publish_date.replace("Z", "+00:00"))

            # Get the affected packages
            for row_pkg in row_vuln['affectedPackages']:
                pkgs = [p for p in json_packages if p['name'] == row_pkg]
                if pkgs:
                    for pkg in pkgs:
                        # Deep copy the json_data_record
                        current_record = deepcopy(json_data_record)

                        current_record.package_name = self._safe_get(pkg,'name')
                        current_record.package_version = self._safe_get(pkg,'version')
                        current_record.package_type = self._safe_get(pkg,'type')
                        current_record.package_path = self._safe_get(pkg,'packagePath')
                        current_record.image = self._safe_get(json_metadata['pullString'])
                        current_record.os_name = self._safe_get(json_metadata['baseOS'])
                        current_record.image_type = self._safe_get(json_metadata,'type')
                        current_record.image_id = self._safe_get(json_metadata['imageID'])
                        current_record.package_suggested_fix = self._safe_get(pkg,'suggestedFix')
                        current_record.vuln_fix_version = current_record.package_suggested_fix

                        arr_json_data.append(current_record)
        return arr_json_data
        