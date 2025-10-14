from logs_parser import LogParser
from point_anomaly_detector import PointAnomalyDetector
from contextual_anomaly_detector import NGramSequenceModel
from alerting_system import AlertManager

if __name__ == "__main__":

    parsing_rules_path = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\parsing_rules.yml"
    anomaly_rules_path = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\anomaly_rules.yml"
    alerting_rules_path = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\alerting_rules.yml"

    authlog_file = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\auth.log"
    syslog_file = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\Linux.log"
    windowslog_file = "C:\\Users\\PC\\PycharmProjects\\LogAnalyzer\\windows_eventlog.json"

    parser = LogParser(parsing_rules_path)
    parsed_authlogs = parser.parse_file(authlog_file, "authlog")
    parsed_syslogs = parser.parse_file(syslog_file, "syslog")
    parsed_windowslogs = parser.parse_file(windowslog_file, "windowslog")

    parsed_logs = (parsed_authlogs + parsed_syslogs + parsed_windowslogs)

    point_detector = PointAnomalyDetector(anomaly_rules_path)
    alert_manager = AlertManager(alerting_rules_path)
    ngram_model = NGramSequenceModel(n=3, min_frequency=2)
    point_anomalies = point_detector.detect(parsed_logs)

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

    sequence = [log["template_id"] for log in parsed_logs if "template_id" in log]
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

