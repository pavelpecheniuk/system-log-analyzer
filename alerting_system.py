import yaml
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertManager:
    def __init__(self, config_path: str, output_file: str = None):
        with open(config_path, "r") as file:
            self.config = yaml.safe_load(file)
        self.console_enabled = self.config["channels"].get("console", True)
        self.email_enabled = self.config["channels"].get("email", False)
        self.allowed_severities = set(self.config.get("filters", {}).get("severity_levels", []))

        if self.email_enabled:
            email_cfg = self.config.get("email", {})
            self.smtp_server = email_cfg.get("smtp_server")
            self.smtp_port = email_cfg.get("smtp_port", 587)
            self.use_tls = email_cfg.get("use_tls", True)
            self.username = email_cfg.get("username")
            self.password = email_cfg.get("password")
            self.from_addr = email_cfg.get("from_addr", self.username)
            self.to_addrs = email_cfg.get("to_addrs", [])

    def send_alert(self, finding: dict):
        severity = finding.get("severity", "low")
        if self.allowed_severities and severity not in self.allowed_severities:
            return
        if self.console_enabled:
            self.send_console(finding)
        if self.email_enabled:
            self.send_email(finding)

    def send_console(self, finding: dict):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"ALERT [{finding['severity'].upper()}]")
        print(f"Time: {ts}")
        print(f"Rule: {finding['rule']}")
        print(f"Details: {finding['details']}")

    def send_email(self, finding: dict):
        try:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                subject = f"[{finding['severity'].upper()}] Anomaly detected - {finding['rule']}"
                body = f"""
                ALERT [{finding['severity'].upper()}]
                Time: {ts}
                Rule: {finding['rule']}
                Details: {finding['details']}
                """

                msg = MIMEMultipart()
                msg["From"] = self.from_addr
                msg["To"] = ", ".join(self.to_addrs)
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain"))

                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls()
                    server.login(self.username, self.password)
                    server.sendmail(self.from_addr, self.to_addrs, msg.as_string())

                print(f"[EMAIL SENT] To: {', '.join(self.to_addrs)}")

        except Exception as e:
                print(f"[EMAIL ERROR] {e}")