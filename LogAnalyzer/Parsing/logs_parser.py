import re
import yaml
import json
import csv
from datetime import datetime

class LogParser:
    def __init__(self, config_path):
        # Loading of parsing rules from the YAML config file
        with open(config_path, "r") as file:
            self.config = yaml.safe_load(file)
        # Mapping regex patterns to template IDs
        self.template_map = {}
        self.next_id = 1

    # Unification of timestamp formats across different logs
    def normalize_ts (self, ts: str, source: str):
        if not ts:
            return None
        try:
            if source in ("authlog", "syslog"):
                # Assuming current year for linux logs, where year is omitted
                current_year = datetime.now().year
                ts_with_year = f"{ts} {current_year}"
                return datetime.strptime(ts_with_year, "%b %d %H:%M:%S %Y")

            elif source == "windowslog":
                # Trying ISO format
                try:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

        except Exception:
            # Returning format unchanged if format failed
            return ts

    # Message generation when not available in parsed data
    def auto_message(self, parsed: dict, log_type: str, file_path: str):
        if "message" in parsed and parsed["message"]:
            return parsed["message"]

        # Fallback message generation
        if log_type in ("windowslog", "windows_csv", "json"):
            return f"Event {parsed.get('event_id', 'UNKNOWN')} by {parsed.get('user', 'UNKNOWN')} on {parsed.get('computer', 'UNKNOWN')}"
        elif log_type in ("authlog", "syslog", "regex"):
            return f"Event {parsed.get('template_id', 'UNKNOWN')} in {file_path or 'logfile'}"
        else:
            return f"Log entry from {file_path or 'unknown source'}"

    # Parsing a log line based on format type
    def parse_line(self, line, log_type, file_path = None):
        parser_config = self.config.get(log_type, {})
        log_format = parser_config.get("format")
        stripped_line = line.strip()

        # Parsing plaintext lines using regular expressions
        if log_format == "regex":
            for pattern in parser_config["patterns"]:
                try:
                    match = re.search(pattern, stripped_line)
                except re.error as e:
                    continue
                if match:
                    # Assignment of a template ID
                    template = pattern
                    if template not in self.template_map:
                        self.template_map[template] = f"T{self.next_id}"
                        self.next_id += 1
                    parsed = match.groupdict()
                    parsed["template_id"] = self.template_map[template]
                    parsed["_source_file"] = file_path
                    # Normalization of timestamps
                    if "timestamp" in parsed:
                        parsed["timestamp"] = self.normalize_ts(parsed.get("timestamp"), log_type)
                    # Ensuring that message always exists
                    parsed["message"] = stripped_line or self.auto_message(parsed, log_type, file_path)
                    return parsed
            return None

        # Parsing JSON logs
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

        # Return if no match observed
        return None

    # Parsing a whole file by delegating it to parse_line() and CSV file reader
    def parse_file(self, file_path, log_type):
        results = []
        parser_config = self.config.get(log_type, {})
        log_format = parser_config.get("format")

        # Parsing CSV logs
        if log_format == "csv":
            with open(file_path, "r", newline="", encoding="utf-8-sig", errors="ignore") as csvfile:
                reader = csv.DictReader(csvfile, delimiter=parser_config.get("delimiter", ","))
                reader.fieldnames = [f.strip().lower() for f in reader.fieldnames]
                for row in reader:
                    if not any(row.values()):
                        continue
                    # Normalization of column names
                    row = {k.strip().lower(): (v.strip() if v else None) for k, v in row.items()}
                    parsed = {}
                    for field, csv_col in parser_config.get("keys_mapping", {}).items():
                        if not csv_col:
                            parsed[field] = None
                            continue
                        parsed[field] = row.get(csv_col.lower(), row.get(csv_col))
                    if not any(parsed.values()):
                        continue
                    # csv_col_norm = csv_col.strip().lower()
                    # parsed[field] = (
                    # row.get(csv_col_norm)
                    # or row.get(csv_col_norm.replace(" ", "_"))
                    # or row.get(csv_col_norm.replace("_", ""))
                    # )
                    parsed["template_id"] = f"E{parsed.get('event_id', 'UNKNOWN')}"
                    if "timestamp" in parsed:
                        parsed["timestamp"] = self.normalize_ts(parsed["timestamp"], log_type)
                    parsed["_source_file"] = file_path
                    parsed["message"] = self.auto_message(parsed, log_type, file_path)
                    results.append(parsed)
                return results
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read().strip()
                # Handling array of JSON objects
                if content.startswith("["):
                    try:
                        data_list = json.loads(content)
                        for data in data_list:
                            parsed = {}
                            for json_field, json_key in parser_config.get("keys_mapping", {}).items():
                                # Case-insensitive key lookup
                                matched_key = next((k for k in data if k.lower() == json_key.lower()), None)
                                parsed[json_field] = data.get(matched_key) if matched_key else None
                            parsed["template_id"] = f"E{parsed.get('event_id', 'UNKNOWN')}"
                            if "timestamp" in parsed:
                                parsed["timestamp"] = self.normalize_ts(parsed["timestamp"], log_type)
                            parsed["_source_file"] = file_path
                            parsed["message"] = self.auto_message(parsed, log_type, file_path)
                            results.append(parsed)
                    except json.JSONDecodeError:
                        print(f"[WARNING] Failed to decode JSON array in {file_path}")
                else:
                    # Fallback for line-based JSON logs
                    for line in content.splitlines():
                        parsed = self.parse_line(line, log_type, file_path=file_path)
                        if parsed:
                            parsed["message"] = self.auto_message(parsed, log_type, file_path)
                            results.append(parsed)

            return results


            #with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
             #   for line in file:
              #      parsed = self.parse_line(line, log_type, file_path=file_path)
               #     if parsed:
                #        parsed["message"] = self.auto_message(parsed, log_type, file_path)
                 #       results.append(parsed)

        #return results

