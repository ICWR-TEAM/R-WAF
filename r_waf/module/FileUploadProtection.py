import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FileUploadProtection:
    def __init__(self, data):
        self.data = data
        self.body = self.data.get("body", "")
        
        self.dangerous_extensions = [
            r"\.php\d?$", r"\.phtml$", r"\.php\d\.suspected$",
            r"\.asp$", r"\.aspx$", r"\.asa$", r"\.cer$", r"\.cdx$",
            r"\.jsp$", r"\.jspx$", r"\.jsw$", r"\.jsv$",
            r"\.exe$", r"\.dll$", r"\.bat$", r"\.cmd$", r"\.com$",
            r"\.scr$", r"\.vbs$", r"\.js$", r"\.jar$",
            r"\.sh$", r"\.bash$", r"\.py$", r"\.pl$", r"\.rb$",
            r"\.cgi$", r"\.htaccess$", r"\.htpasswd$",
            r"\.war$", r"\.ear$", r"\.swf$", r"\.svg$"
        ]
        
        self.shell_signatures = [
            b"<?php",
            b"<%",
            b"<script",
            b"eval(",
            b"base64_decode",
            b"system(",
            b"exec(",
            b"passthru(",
            b"shell_exec",
            b"proc_open",
            b"popen(",
            b"curl_exec",
            b"curl_multi_exec",
            b"assert(",
            b"create_function",
            b"file_get_contents",
            b"file_put_contents",
            b"fopen(",
            b"readfile(",
            b"require(",
            b"include("
        ]
        
        self.max_upload_size = 10 * 1024 * 1024

    def run(self):
        if "status_code" in self.data and self.data["status_code"] is not None:
            return {"action": "allow", "result": "skipped_response_phase"}
        
        method = self.data.get("method", "")
        if method.upper() not in ["POST", "PUT"]:
            return {"action": "allow", "result": "not_upload_request"}
        
        header = self.data.get("header", "")
        try:
            import base64
            header_decoded = base64.b64decode(header.encode()).decode() if header else ""
        except:
            header_decoded = ""
        
        if "multipart/form-data" not in header_decoded.lower():
            return {"action": "allow", "result": "not_file_upload"}
        
        try:
            import base64
            body_decoded = base64.b64decode(self.body.encode()) if self.body else b""
        except:
            body_decoded = b""
        
        if len(body_decoded) > self.max_upload_size:
            logger.warning(f"Oversized file upload from {self.data['ip']}: {len(body_decoded)} bytes")
            return {
                "action": "block",
                "reason": f"File upload too large: {len(body_decoded)} bytes",
                "result": {"size": len(body_decoded), "limit": self.max_upload_size}
            }
        
        filename_match = re.search(rb'filename="([^"]+)"', body_decoded)
        if filename_match:
            filename = filename_match.group(1).decode('utf-8', errors='ignore')
            
            for ext_pattern in self.dangerous_extensions:
                if re.search(ext_pattern, filename, re.IGNORECASE):
                    logger.warning(f"Dangerous file extension from {self.data['ip']}: {filename}")
                    return {
                        "action": "block",
                        "reason": f"Dangerous file extension detected: {filename}",
                        "result": {"filename": filename, "matched_pattern": ext_pattern}
                    }
            
            if ".." in filename or "/" in filename or "\\" in filename:
                logger.warning(f"Path traversal in filename from {self.data['ip']}: {filename}")
                return {
                    "action": "block",
                    "reason": "Path traversal detected in filename",
                    "result": {"filename": filename}
                }
        
        for signature in self.shell_signatures:
            if signature in body_decoded:
                logger.warning(f"Web shell signature detected from {self.data['ip']}")
                return {
                    "action": "block",
                    "reason": "Web shell or malicious code detected in upload",
                    "result": {"signature": signature.decode('utf-8', errors='ignore')[:50]}
                }
        
        double_ext_pattern = rb'\.(?:jpg|png|gif|txt|pdf)\.(?:php|asp|jsp|exe)'
        if re.search(double_ext_pattern, body_decoded, re.IGNORECASE):
            logger.warning(f"Double extension attack from {self.data['ip']}")
            return {
                "action": "block",
                "reason": "Double extension attack detected",
                "result": {"pattern": "double_extension"}
            }
        
        return {"action": "allow", "result": {"file_upload_check": "passed"}}

def run(data):
    return FileUploadProtection(data).run()
