from dojo.models import Finding
import datetime
import csv
import io

class SysdigData:

    def _map_severity(self, severity):
        severity_mapping = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "NEGLIGIBLE": "Informational"
        }
    
        return severity_mapping.get(severity, "Informational")
    
    """
    Data class to represent the Sysdig data extracted from sources CSV
    """
    def __init__(self):
        self.vulnerability_id: str = ""
        self.url: str = ""
        self.severity: str = ""
        self.package_name: str = ""
        self.package_version: str = ""
        self.package_type: str = ""
        self.package_path: str = ""
        self.image: str  = ""
        self.os_name: str = ""
        self.cvss_version: float = 0
        self.cvss_score: float = 0
        self.cvss_vector: str = ""
        self.vuln_link: str = ""
        self.vuln_publish_date: str = ""
        self.vuln_fix_date: datetime.date = None
        self.vuln_fix_version: str = ""
        self.public_exploit: str = ""
        self.k8s_cluster_name: str = ""
        self.k8s_namespace_name: str = ""
        self.k8s_workload_type: str = ""
        self.k8s_workload_name: str  = ""
        self.k8s_container_name: str  = ""
        self.image_id: str = ""
        self.k8s_pod_count: str = 0
        self.package_suggested: str = ""
        self.in_use: bool  = False
        self.risk_accepted: bool = False
        self.publish_date: datetime.date = None
        self.component_version: str = ""
        self.package_suggested_fix: str = ""
        self.image_type: str = ""
        self.registry_name: str = ""
        self.registry_image_repository: str = ""
        
class sysdigParser(object):
    """
    Sysdig Report Importer - Runtime CSV
    """

    def get_scan_types(self):
        return ["Sysdig Vulnerability Report Scan - Runtime CSV"]

    def get_label_for_scan_types(self, scan_type):
        return "Sysdig Runtime Vulnerability Report Scan in CSV"
 
    def get_description_for_scan_types(self, scan_type):
        return "Import of Sysdig Runtime Vulnerability Report Scan in CSV format"

    def parse(self, filename) -> SysdigData: 

        if filename is None:
            return ()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        arr_csv_data = []
        
        for row in csvarray:
            csv_data_record = SysdigData()

            csv_data_record.vulnerability_id = row.get('Vulnerability ID','')
            csv_data_record.severity = csv_data_record._map_severity(row.get('Severity').upper())
            csv_data_record.package_name = row.get('Package name','')
            csv_data_record.package_version = row.get('Package version','')
            csv_data_record.package_type = row.get('Package type','')
            csv_data_record.package_path = row.get('Package path','')
            csv_data_record.image = row.get('Image','')
            csv_data_record.os_name = row.get('OS Name','')
            csv_data_record.cvss_version = row.get('CVSS version','')
            csv_data_record.cvss_score = row.get('CVSS score','')
            csv_data_record.cvss_vector = row.get('CVSS vector','')
            csv_data_record.vuln_link = row.get('Vuln link','')
            csv_data_record.vuln_publish_date = row.get('Vuln Publish date','')
            csv_data_record.vuln_fix_date = row.get('Vuln Fix date','')
            csv_data_record.vuln_fix_version = row.get('Fix version','')
            csv_data_record.public_exploit = row.get('Public Exploit','')
            csv_data_record.k8s_cluster_name = row.get('K8S cluster name','')
            csv_data_record.k8s_namespace_name = row.get('K8S namespace name','')
            csv_data_record.k8s_workload_type = row.get('K8S workload type','')
            csv_data_record.k8s_workload_name = row.get('K8S workload name','')
            csv_data_record.k8s_container_name = row.get('K8S container name','')
            csv_data_record.image_id = row.get('Image ID','')
            csv_data_record.k8s_pod_count = row.get('K8S POD count','')
            csv_data_record.package_suggested_fix = row.get('Package suggested fix','')
            csv_data_record.in_use = row.get('In use','') == 'TRUE'
            csv_data_record.risk_accepted = row.get('Risk accepted','') == 'TRUE'
            csv_data_record.registry_name = row.get('Registry name','')
            csv_data_record.registry_image_repository = row.get('Registry image repository','')

            arr_csv_data.append(csv_data_record)

        return arr_csv_data

    def get_findings(self, filename, test):

        if filename is None:
            return ()

        if filename.name.lower().endswith('.csv'):
            arr_data = self.parse(filename=filename)
        else:
            return ()
        
        if len(arr_data) == 0:
            return ()
        sysdig_report_findings = []
        
        for row in arr_data:
            finding = Finding(test=test)

            # Generate finding
            if row.k8s_cluster_name != "":
                finding.title = f"{row.k8s_cluster_name} - {row.k8s_namespace_name} - {row.package_name} - {row.vulnerability_id}"
            else:
                finding.title = f"{row.vulnerability_id} - {row.package_name}"

            finding.vuln_id_from_tool = row.vulnerability_id
            finding.cve = row.vulnerability_id
            finding.severity = row.severity

            # Set Component Version
            finding.component_name = row.package_name
            finding.component_version = row.package_version
            
            # Set some finding tags
            tags = []

            if row.k8s_cluster_name != "":
                tags.append("Cluster: " + row.k8s_cluster_name)
            if row.k8s_namespace_name != "":
                tags.append("Namespace: " + row.k8s_namespace_name)
            if row.k8s_workload_name != "":
                tags.append("WorkloadName: " + row.k8s_workload_name)
            if row.package_name != "":
                tags.append("PackageName: " + row.package_name)
            if row.package_version != "":
                tags.append("PackageVersion: " + row.package_version)
            if row.k8s_cluster_name != "":
                tags.append("InUse: " + str(row.in_use))
 
            finding.tags = tags

            # Build Description
            if row.k8s_cluster_name != "":
                finding.dynamic_finding = True
                finding.static_finding = False
                finding.description += f"###Runtime Context {row.k8s_cluster_name}"
                finding.description += f"\n - **Cluster:** {row.k8s_cluster_name}"
                finding.description += f"\n - **Namespace:** {row.k8s_namespace_name}"
                finding.description += f"\n - **Workload Name:** {row.k8s_workload_name} "
                finding.description += f"\n - **Workload Type:** {row.k8s_workload_type} "
                finding.description += f"\n - **Container Name:** {row.k8s_container_name}"
            else:
                finding.dynamic_finding = False
                finding.static_finding = True

            finding.description += f"\n\n###Vulnerability Details"
            finding.description += f"\n - **Vulnerability ID:** {row.vulnerability_id}"
            finding.description += f"\n - **Vulnerability Link:** {row.vuln_link}"
            finding.description += f"\n - **Severity:** {row.severity}"
            finding.description += f"\n - **Publish Date:** {row.vuln_publish_date}"
            finding.description += f"\n - **CVSS Version:** {row.cvss_version}"
            finding.description += f"\n - **CVSS Vector:** {row.cvss_vector}"

            if row.public_exploit != '':
                finding.description += (f"\n - **Public Exploit:** {row.public_exploit}")
            
            finding.description += f"\n\n###Package Details"
            if row.package_type == "os":
                finding.description += f"\n - **Package Type: {row.package_type} \\* Consider upgrading your Base OS \\***"
            else:
                finding.description += f"\n - **Package Type:** {row.package_type}"
            finding.description += f"\n - **Package Name:** {row.package_name}"
            finding.description += f"\n - **Package Version:** {row.package_version}"
            finding.description += f"\n - **In-Use:** {row.in_use}"

            if row.package_path != '':
                finding.description += f"\n - **Package Path:** {row.package_path}"                       
            if row.package_suggested_fix != '':    
                finding.mitigation = f"Package suggested fix version: {row.package_suggested_fix}"
                finding.description += f"\n - **Package suggested fix version:** {row.package_suggested_fix}"
                if row.package_type == "os":
                    finding.mitigation += f"\n\\*** Consider upgrading your Base OS \\***"

            finding.description += f"\n\n###Image Details"
            finding.description += f"\n - **Image Name:** {row.image}"
            finding.description += f"\n - **Image OS:** {row.os_name}"
            finding.description += f"\n - **Image ID:** {row.image_id}"
            
            # If we have registry information
            if row.registry_name != "":
                finding.description +=  (f"\n - **Registry Name:** {row.registry_name}" +
                                        f"\n - **Registy Image Repository:** {row.registry_image_repository}")

            try:
                if float(row.cvss_version) >= 3:
                    finding.cvssv3_score = row.cvss_score
            except ValueError:
                continue

            finding.risk_accepted = row.risk_accepted

            # Set reference
            if row.vuln_link != "":
                finding.references = row.vuln_link
                finding.url = row.vuln_link

            # Add finding to list
            sysdig_report_findings.append(finding)

        return sysdig_report_findings
    