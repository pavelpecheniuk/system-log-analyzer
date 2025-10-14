import re
import statistics
import yaml
from typing import List, Dict, Any, Optional

class PointAnomalyDetector:
    def __init__(self, config_path: str):
        with open(config_path, "r") as file:
            config = yaml.safe_load(file) or {}
        rules = (config.get("point_anomalies") or {})
        self.template_rules: List[str] = rules.get("template_rules") or []
        self.attribute_fields: List[str] = rules.get("attribute_fields") or []
        self.iqr_factor: float = rules.get("iqr_factor", 1.5)

    def get_message_text(self, log_entry: Dict[str, Any]) -> str:
        return (log_entry.get("message") or log_entry.get("details") or log_entry.get("raw") or "")

    def safe_float(self, val: Any) -> Optional[float]:
        if val is None:
            return None
        s = str(val).strip()
        for suf in ["%", "ms", "s"]:
            if s.endswith(suf):
                s = s[: -len(suf)].strip()
        s = s.replace(",", "")
        try:
            return float(s)
        except Exception:
            return None

    def find_field_value(self, log: Dict[str, Any], field: str):
        if field in log:
            return log[field]
        if field.lower() in log:
            return log[field.lower()]
        target = field.lower().replace("_", "")
        for k, v in log.items():
            if k and k.lower().replace("_", "") == target:
                return v
        return None

    def detect_template_anomaly(self, log_entry: Dict[str, Any]) -> bool:
        message = self.get_message_text(log_entry)
        for pattern in self.template_rules:
            try:
                if re.search(pattern, message):
                    return True
            except re.error as e:
                print(f"Invalid regex pattern '{pattern}': {e}")
        return False

    def detect_attribute_anomaly(self, parsed_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not parsed_logs:
            return []
        point_anomalies: List[Dict[str, Any]] = []

        try:
            fields = self.attribute_fields or []
            for field in fields:
                values = []
                for log in parsed_logs:
                    raw = self.find_field_value(log, field)
                    num = self.safe_float(raw)
                    if num is not None:
                        values.append(num)

                if len(values) < 4:
                    continue

                sorted_values = sorted(values)
                q1 = statistics.quantiles(sorted_values, n=4)[0]  # 25th percentile
                q3 = statistics.quantiles(sorted_values, n=4)[2]  # 75th percentile
                iqr = q3 - q1

                lower_bound = q1 - self.iqr_factor * iqr
                upper_bound = q3 + self.iqr_factor * iqr

                for log in parsed_logs:
                    raw = self.find_field_value(log, field)
                    num = self.safe_float(log.get(field))
                    if num is not None and (num < lower_bound or num > upper_bound):
                        flagged = log.copy()
                        flagged["anomaly_field"] = field
                        flagged["anomaly_value"] = num
                        point_anomalies.append(flagged)

        except Exception as e:
            print("Error during attribute anomaly detection:", e)

        return point_anomalies

    def detect(self, parsed_logs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        parsed_logs = parsed_logs or []
        template_anomalies: List[Dict[str, Any]] = []
        for log in parsed_logs:
            try:
                if self.detect_template_anomaly(log):
                    log_with_sev = log.copy()
                    log_with_sev["severity"] = "high"
                    template_anomalies.append(log_with_sev)
            except Exception as e:
                print("Error checking template anomaly for log:", e)

        try:
            attr_results = self.detect_attribute_anomaly(parsed_logs)
            if attr_results is None:
                attr_results = []
        except Exception as e:
            print("detect_attribute_anomaly raised exception:", e)
            attr_results = []

        attribute_anomalies: List[Dict[str, Any]] = []
        for log in attr_results:
            try:
                log_with_sev = log.copy()
                log_with_sev["severity"] = "medium"
                attribute_anomalies.append(log_with_sev)
            except Exception as e:
                print("Error tagging severity for attribute anomaly:", e)

        return {
            "template_anomalies": template_anomalies,
            "attribute_anomalies": attribute_anomalies
        }

