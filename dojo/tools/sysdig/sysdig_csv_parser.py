import csv
import io
from dojo.tools.sysdig.sysdig_data import SysdigData

class CSVParser:
    """
    Sysdig CSV Data Parser
    """

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

            arr_csv_data.append(csv_data_record)

        return arr_csv_data
        