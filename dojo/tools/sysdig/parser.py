from dojo.models import Finding
from dojo.tools.sysdig.sysdig_csv_parser import CSVParser
from dojo.tools.sysdig.sysdig_json_parser import JSONParser

class sysdigParser(object):
    """
    Sysdig Report Importer
    """

    def get_scan_types(self):
        return ["Sysdig Vulnerability Report Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Sysdig Pipeline, Registry & Runtime Vulnerability Report Scan"
 
    def get_description_for_scan_types(self, scan_type):
        return "Import of Sysdig Pipeline, Registry & Runtime Vulnerability Report Scans in CSV format."

    def get_findings(self, filename, test):

        if filename is None:
            return ()

        if filename.name.lower().endswith('.csv'):
            arr_data = CSVParser().parse(filename=filename)
        elif filename.name.lower().endswith('.json'):
            arr_data = JSONParser().parse(filename=filename)
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

            finding.vuln_id_from_tool = finding.cve = row.vulnerability_id
            finding.severity = row.severity

            if row.k8s_cluster_name != "":
                finding.description = (f"###Runtime Context {row.k8s_cluster_name}" +
                                        f"\n - **Cluster:** {row.k8s_cluster_name}" +
                                        f"\n - **Namespace:** {row.k8s_namespace_name}" +
                                        f"\n - **Workload Name:** {row.k8s_workload_name} " +
                                        f"\n - **Workload Type:** {row.k8s_workload_type} " +
                                        f"\n - **Container Name:** {row.k8s_container_name}"
                )
            finding.description += (f"\n\n###Vulnerability Details" + 
                                    f"\n - **Vulnerability ID:** {row.vulnerability_id}" +
                                    f"\n - **Severity:** {row.severity}" + 
                                    f"\n - **Publish Date:** {row.vuln_publish_date}" +
                                    f"\n - **CVSS Version:** {row.cvss_version}" +
                                    f"\n - **CVSS Vector:** {row.cvss_vector}"
                                    )
            if row.public_exploit != '':
                finding.description += (f"\n - **Public Exploit:** {row.public_exploit}")
            
            finding.description += (f"\n\n###Package Details" +
                                    f"\n - **Package Type:** {row.package_type}" +
                                    f"\n - **Package Name:** {row.package_name}" +
                                    f"\n - **Package Version:** {row.package_version}" +
                                    f"\n - **In-Use:** {row.in_use}"
            )
            if row.package_path != '':
                finding.description += f"\n - **Package Path:** {row.package_path}"                       
            if row.package_suggested_fix != '':    
                finding.mitigation = f"Package suggested fix version: {row.package_suggested_fix}"
                finding.description += (f"\n - **Package suggested fix version:** {row.package_suggested_fix}")

            finding.description += (f"\n\n###Image Details" +
                                    f"\n - **Image Name:** {row.image}" +
                                    f"\n - **Image OS:** {row.os_name}" +
                                    f"\n - **Image ID:** {row.image_id}"
            )

            try:
                if float(row.cvss_version) >= 3:
                    finding.cvssv3_score = row.cvss_score
            except ValueError:
                continue

            finding.risk_accepted = row.risk_accepted
            finding.url = row.vuln_link
            finding.dynamic_finding = True

            # Add finding to list
            sysdig_report_findings.append(finding)

        return sysdig_report_findings
        