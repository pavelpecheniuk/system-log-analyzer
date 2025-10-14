import re
import yaml
import json
import csv
from datetime import datetime

class LogParser:
    def __init__(self, config_path):
        with open(config_path, "r") as file:
            self.config = yaml.safe_load(file)
        self.template_map = {}
        self.next_id = 1

    def normalize_ts (self, ts: str, source: str):
        if not ts:
            return None
        try:
            if source in ("authlog", "syslog"):
                current_year = datetime.now().year
                ts_with_year = f"{ts} {current_year}"
                return datetime.strptime(ts_with_year, "%b %d %H:%M:%S %Y")

            elif source == "windowslog":
                try:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

        except Exception:
            return ts

    def auto_message(self, parsed: dict, log_type: str, file_path: str):
        if "message" in parsed and parsed["message"]:
            return parsed["message"]

        if log_type in ("windowslog", "windows_csv", "json"):
            return f"Event {parsed.get('event_id', 'UNKNOWN')} by {parsed.get('user', 'UNKNOWN')} on {parsed.get('computer', 'UNKNOWN')}"
        elif log_type in ("authlog", "syslog", "regex"):
            return f"Event {parsed.get('template_id', 'UNKNOWN')} in {file_path or 'logfile'}"
        else:
            return f"Log entry from {file_path or 'unknown source'}"

    def parse_line(self, line, log_type, file_path = None):
        parser_config = self.config.get(log_type, {})
        log_format = parser_config.get("format")
        stripped_line = line.strip()

        if log_format == "regex":
            for pattern in parser_config["patterns"]:
                try:
                    match = re.search(pattern, stripped_line)
                except re.error as e:
                    continue
                if match:
                    template = pattern
                    if template not in self.template_map:
                        self.template_map[template] = f"T{self.next_id}"
                        self.next_id += 1
                    parsed = match.groupdict()
                    parsed["template_id"] = self.template_map[template]
                    parsed["_source_file"] = file_path
                    if "timestamp" in parsed:
                        parsed["timestamp"] = self.normalize_ts(parsed.get("timestamp"), log_type)
                    parsed["message"] = stripped_line or self.auto_message(parsed, log_type, file_path)
                    return parsed
            return None

        elif log_format == "json":
            if stripped_line.startswith("{") and stripped_line.endswith("}"):
                try:
                    data = json.loads(stripped_line)
                except json.JSONDecodeError:
                    return None
                parsed = {}
                for json_field, json_key in parser_config.get("keys_mapping", {}).items():
                    parsed[json_field] = data.get(json_key)
                parsed["template_id"] = f"E{parsed.get('event_id', 'UNKNOWN')}"
                if "timestamp" in parsed:
                    parsed["timestamp"] = self.normalize_ts(parsed["timestamp"], log_type)
                parsed["_source_file"] = file_path
                parsed["message"] = self.auto_message(parsed, log_type, file_path)
                return parsed

        elif log_format == "csv":
            return None

        return None

    def parse_file(self, file_path, log_type):
        results = []
        parser_config = self.config.get(log_type, {})
        log_format = parser_config.get("format")

        if log_format == "csv":
            with open(file_path, "r", newline="", encoding="utf-8", errors="ignore") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    row = {k.strip().lower(): v for k, v in row.items() if k}
                    parsed = {}
                    for field, csv_col in parser_config.get("keys_mapping", {}).items():
                        if not csv_col:
                            parsed[field] = None
                            continue
                        parsed[field] = row.get(csv_col.lower(), row.get(csv_col))
                    parsed["template_id"] = f"E{parsed.get('event_id', 'UNKNOWN')}"
                    if "timestamp" in parsed:
                        parsed["timestamp"] = self.normalize_ts(parsed["timestamp"], log_type)
                    parsed["_source_file"] = file_path
                    parsed["message"] = self.auto_message(parsed, log_type, file_path)
                    results.append(parsed)
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                for line in file:
                    parsed = self.parse_line(line, log_type, file_path=file_path)
                    if parsed:
                        parsed["message"] = self.auto_message(parsed, log_type, file_path)
                        results.append(parsed)

        return results

