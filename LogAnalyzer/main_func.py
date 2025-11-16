from Parsing.logs_parser import LogParser
from Anomaly_Detection.point_anomaly_detector import PointAnomalyDetector
from Anomaly_Detection.contextual_anomaly_detector import NGramSequenceModel
from Alerting.alerting_system import AlertManager

def calculate_parse_success(file_path, parsed_results):
     # Calculate and print the parsing success rate for a log file
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            total_lines = sum(1 for _ in f if _.strip())
        success_rate = (len(parsed_results) / total_lines) * 100 if total_lines > 0 else 0
        print(f"[INFO] {file_path} → {len(parsed_results)} / {total_lines} lines parsed successfully "
              f"({success_rate:.2f}%)")
        return total_lines, len(parsed_results)
    except Exception as e:
        print(f"[ERROR] Could not calculate parse success rate for {file_path}: {e}")
        return 0.0

if __name__ == "__main__":

    # Connection of all components needed for analysis altogether
    parsing_rules_path = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\Parsing\\parsing_rules.yml"
    anomaly_rules_path = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\Anomaly_Detection\\anomaly_rules.yml"
    alerting_rules_path = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\Alerting\\alerting_rules.yml"

    #authlog_file = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\Plaintext_Logs\\AuthLog (LinuxLog_10).log"
    syslog_file = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\Plaintext_Logs\\LinuxLog_7.log"
    #windowslog_file = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\JSON_Logs\\JSON_Log_2.json"
    #windowslog_csv = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\CSV_Logs\\WindowsLog_1.csv"

    parser = LogParser(parsing_rules_path)
    #parsed_authlogs = parser.parse_file(authlog_file, "authlog")
    parsed_syslogs = parser.parse_file(syslog_file, "syslog")
    #parsed_windowslogs = parser.parse_file(windowslog_file, "windowslog")
    #parsed_windowslogs_csv = parser.parse_file(windowslog_csv, "windows_csv")

    #parsed_authlogs = parsed_authlogs or []
    parsed_syslogs = parsed_syslogs or []
    #parsed_windowslogs = parsed_windowslogs or []
    #parsed_windowslogs_csv = parsed_windowslogs_csv or []

    total_lines_sum = 0
    total_parsed_sum = 0

    for path, data in [
        #(authlog_file, parsed_authlogs),
        #(syslog_file, parsed_syslogs),
        #(windowslog_file, parsed_windowslogs),
        #(windowslog_csv, parsed_windowslogs_csv),
    ]:
        total, parsed = calculate_parse_success(path, data)
        total_lines_sum += total
        total_parsed_sum += parsed

    # Display total parsing success summary ###
    if total_lines_sum > 0:
        overall_success = (total_parsed_sum / total_lines_sum) * 100
        print(f"\n[SUMMARY] Overall parsing success rate: {overall_success:.2f}% "
              f"({total_parsed_sum}/{total_lines_sum} total lines parsed)\n")
    else:
        print("\n[SUMMARY] No log files processed.\n")

    parsed_logs = (parsed_syslogs)

    point_detector = PointAnomalyDetector(anomaly_rules_path)
    alert_manager = AlertManager(alerting_rules_path)
    ngram_model = NGramSequenceModel(n=3, min_frequency=2)
    point_anomalies = point_detector.detect(parsed_logs)

    # Displaying anomalies in a structured way
    print("\n--- Point Anomalies ---")
    for anomaly in point_anomalies["template_anomalies"]:
        finding = {
            "severity": anomaly["severity"],
            "rule": "Template Anomaly",
            "details": anomaly
        }
        alert_manager.send_alert(finding)

    for anomaly in point_anomalies["attribute_anomalies"]:
        finding = {
            "severity": anomaly["severity"],
            "rule": "Attribute Anomaly",
            "details": anomaly
        }
        alert_manager.send_alert(finding)

    flagged_ids = {log.get("template_id") for log in (
            point_anomalies["template_anomalies"] + point_anomalies["attribute_anomalies"]
    )}
    filtered_logs = [log for log in parsed_logs if log.get("template_id") not in flagged_ids]
    sequence = [log["template_id"] for log in filtered_logs if "template_id" in log]
    ngram_model.train(sequence)
    context_anomalies = ngram_model.detect(sequence)

    print("\n--- Contextual Anomalies ---")

    for anomaly in context_anomalies:
        start_idx = anomaly["position"]
        ngram_length = len(anomaly["ngram"])

        log_messages = []
        for i in range(start_idx, start_idx + ngram_length):
            if i < len(parsed_logs):
                log_messages.append(parsed_logs[i].get("message", str(parsed_logs[i])))

        finding = {
            "severity": anomaly.get("severity", "low"),
            "rule": "Contextual Anomaly",
            "details": {
                "ngram": anomaly["ngram"],
                "position": anomaly["position"],
                "messages": log_messages,
                "_source_file": parsed_logs[start_idx].get("_source_file", "UNKNOWN")
            }
        }
        alert_manager.send_alert(finding)





    #total, parsed = calculate_parse_success(path, data)
    #total_lines_sum += total
    #total_parsed_sum += parsed

    # Display total parsing success summary ###
    #if total_lines_sum > 0:
        #overall_success = (total_parsed_sum / total_lines_sum) * 100
        #print(f"\n[SUMMARY] Overall parsing success rate: {overall_success:.2f}% "
              #f"({total_parsed_sum}/{total_lines_sum} total lines parsed)\n")
    #else:
        #print("\n[SUMMARY] No log files processed.\n")

    #if total > 0:
        #success_rate = (parsed / total) * 100
        #print(f"[INFO] {path} → Parse success rate: {success_rate:.2f}% ({parsed}/{total})")
    #else:
        #print(f"[WARNING] No lines found in {path}.")