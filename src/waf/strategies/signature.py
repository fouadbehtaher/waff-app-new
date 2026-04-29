import re
import structlog
from models.request import RequestMetadata, AIStrategyResult, Decision, ThreatLevel
from strategies.base import Strategy
from waf_config import waf_config

logger = structlog.get_logger()

SQL_INJECTION_PATTERNS = [
    (r"('|%27)(\s)*(or|and)(\s)*('|%27|\d|=)", "sql_injection_or_and"),
    (r"(union(\s)+select)", "sql_injection_union"),
    (r"(drop|delete|insert|update)(\s)+(table|from|into|set)", "sql_injection_dml"),
    (r"(--|;|#)(\s)*$", "sql_comment_injection"),
    (r"(\b)(waitfor(\s)+delay|benchmark\(|sleep\()", "sql_injection_blind"),
    (r"(\b)(1\s*=\s*1|1\s*=\s*2|'1'\s*=\s*'1')", "sql_injection_boolean"),
    (r"(information_schema|sysobjects|syscolumns)", "sql_injection_metadata"),
    (r"(char\(|convert\(|cast\(|concat\(|group_concat\()", "sql_injection_functions"),
    (r"(load_file|into\s+outfile|into\s+dumpfile)", "sql_injection_file"),
    (r"(xp_cmdshell|sp_executesql|exec(\s)*\()", "sql_injection_procedures"),
    (r"(HAVING\s+\d|ORDER\s+BY\s+\d)", "sql_injection_error_based"),
]

XSS_PATTERNS = [
    (r"<script[^>]*>", "xss_script_tag"),
    (r"javascript\s*:", "xss_javascript_uri"),
    (r"on(error|load|click|mouseover|focus|blur|input|change|submit|keydown|keyup|keypress|mouseout|mouseenter|dblclick|contextmenu)\s*=", "xss_event_handler"),
    (r"<iframe[^>]*>", "xss_iframe"),
    (r"<svg[^>]*on\w+\s*=", "xss_svg_event"),
    (r"<img[^>]*src\s*=\s*['\"]?javascript:", "xss_img_js"),
    (r"<embed[^>]*src", "xss_embed"),
    (r"<object[^>]*data", "xss_object"),
    (r"<marquee[^>]*onstart", "xss_marquee"),
    (r"document\.(cookie|write|location|domain)", "xss_dom_access"),
    (r"window\.(location|open|alert|confirm|prompt)", "xss_window_methods"),
    (r"eval\(|setTimeout\(|setInterval\(|Function\(", "xss_execution"),
    (r"<img\s+src\s*=\s*['\"]?\s*onerror", "xss_img_onerror"),
    (r"(<|%3C)svg.*onload", "xss_svg_onload"),
    (r"(%0d%0a|%0d|%0a)", "xss_header_injection"),
]

SSTI_PATTERNS = [
    (r"\{\{.*\}\}", "ssti_jinja2"),
    (r"\$\{.*\}", "ssti_expression"),
    (r"<%[=]?\s*.*\s*%>", "ssti_erb_asp"),
    (r"\{\%.*\%\}", "ssti_jinja2_block"),
    (r"\#set\s*\(", "ssti_velocity"),
    (r"#{.*}", "ssti_ruby_interpolation"),
    (r"\[\[.*\]\]", "ssti_freemarker"),
    (r"__class__|__mro__|__subclasses__|__globals__|__builtins__", "ssti_python_internals"),
    (r"config\s*\[\s*['\"]", "ssti_flask_config"),
    (r"self\s*\.\s*__init__", "ssti_python_self"),
    (r"request\s*\.\s*application", "ssti_flask_request"),
    (r"cycler\s*\.\s*__init__", "ssti_jinja_cycler"),
    (r"joiner\s*\.\s*__init__", "ssti_jinja_joiner"),
    (r"namespace\s*\.\s*__init__", "ssti_jinja_namespace"),
]

SSI_PATTERNS = [
    (r"<!--\s*#include\s+(file|virtual)\s*=", "ssi_include"),
    (r"<!--\s*#exec\s+cmd\s*=", "ssi_exec"),
    (r"<!--\s*#echo\s+var\s*=", "ssi_echo"),
    (r"<!--\s*#set\s+var\s*=", "ssi_set"),
    (r"<!--\s*#if\s+expr\s*=", "ssi_if"),
    (r"<!--\s*#printenv", "ssi_printenv"),
    (r"<!--\s*#flastmod", "ssi_flastmod"),
    (r"<!--\s*#fsize", "ssi_fsize"),
]

XXE_XML_PATTERNS = [
    (r"<!DOCTYPE[^>]*\[", "xxe_doctype"),
    (r"<!ENTITY[^>]*SYSTEM", "xxe_entity_system"),
    (r"<!ENTITY[^>]*PUBLIC", "xxe_entity_public"),
    (r"<!ENTITY[^>]*SYSTEM\s*['\"]\s*file://", "xxe_file_access"),
    (r"<!ENTITY[^>]*SYSTEM\s*['\"]\s*http://", "xxe_http_access"),
    (r"<!ENTITY[^>]*SYSTEM\s*['\"]\s*expect://", "xxe_expect_access"),
    (r"<!ENTITY[^>]*SYSTEM\s*['\"]\s*php://filter", "xxe_php_filter"),
    (r"<!ENTITY[^>]*SYSTEM\s*['\"]\s*data://", "xxe_data_access"),
    (r"<\?xml\s+version.*encoding", "xml_declaration"),
    (r"CDATA\[", "xml_cdata"),
    (r"<!ELEMENT[^>]*ANY", "xml_element_any"),
    (r"<!ATTLIST", "xml_attlist"),
    (r"(application/xml|text/xml|application/xhtml)", "xml_content_type"),
    (r"<soap:Envelope|<soapenv:Envelope", "soap_envelope"),
    (r"<svg[^>]*xmlns", "svg_namespace"),
]

COMMAND_INJECTION_PATTERNS = [
    (r";\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|nc|ncat|netcat|id|whoami|uname|pwd|ipconfig|ifconfig|net\s+user|systeminfo)\b", "command_injection_direct"),
    (r"\|\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|id|whoami|uname|pwd)", "command_injection_pipe"),
    (r"`[^`]*`", "command_injection_backtick"),
    (r"\$\([^)]*\)", "command_injection_subshell"),
    (r"&&\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|id|whoami)", "command_injection_and"),
    (r"\|\|\s*(ls|cat|rm|wget|curl|bash|sh)", "command_injection_or"),
    (r"\b(eval|exec|passthru|system|popen|proc_open|shell_exec|pcntl_exec)\s*\(", "command_injection_functions"),
    (r"(\/bin\/(sh|bash|zsh|csh|ksh|dash))", "command_injection_shell"),
    (r"(cmd\.exe|powershell|powershell\.exe|wscript|cscript)", "command_injection_windows"),
    (r"(net\s+user|net\s+localgroup|whoami|ipconfig|systeminfo|tasklist|netstat)", "command_injection_recon"),
]

FILE_INCLUSION_PATTERNS = [
    (r"(\.\./|\.\.\\)", "file_inclusion_traversal"),
    (r"%2e%2e(%2f|%5c|/|\\)", "file_inclusion_encoded"),
    (r"/etc/(passwd|shadow|hosts|group|issue|fstab|mtab|resolv\.conf)", "file_inclusion_linux"),
    (r"C:\\(Windows|winnt|boot\.ini|autoexec\.bat)", "file_inclusion_windows"),
    (r"(php|expect|zip|data|input|filter|glob|phar)://", "file_inclusion_php_wrappers"),
    (r"(https?|ftp|php|file|zlib|ssh2|rar|ogg)://", "file_inclusion_rfi"),
    (r"(include|require|include_once|require_once)\s*\(", "file_inclusion_php_functions"),
    (r"\.(php|asp|aspx|jsp|jspx|cgi|pl)\?", "file_inclusion_extension"),
    (r"(readfile|file_get_contents|file|fopen|fread)\s*\(", "file_inclusion_read_functions"),
    (r"/proc/self/environ", "file_inclusion_proc"),
]

FILE_UPLOAD_PATTERNS = [
    (r"Content-Disposition:\s*form-data.*filename\s*=", "file_upload_multipart"),
    (r"application/octet-stream", "file_upload_octet_stream"),
    (r"\.(php|php3|php4|php5|phtml|asp|aspx|jsp|jspx|cgi|pl|py|rb|exe|bat|cmd|com|sh)\b", "file_upload_executable_extension"),
    (r"Content-Type:\s*(application/x-httpd-php|application/x-php|text/x-php)", "file_upload_php_content_type"),
    (r"#!/(usr/bin/(python|perl|ruby|php)|bin/(sh|bash|zsh))", "file_upload_shebang"),
    (r"<\?php|<%=|<%", "file_upload_code_injection"),
    (r"(GIF89a|GIF87a|%89PNG|JFIF|II\x2a\x00)", "file_upload_magic_bytes"),
    (r"PHPEditor|Sublime|Notepad", "file_upload_editor_metadata"),
    (r"(Exif|JFIF|Photoshop|XMP)", "file_upload_metadata"),
    (r"\x00\x00\x00(\\|\/|\.)", "file_upload_null_byte"),
]

DOM_XSS_SOURCE_SINK_PATTERNS = [
    (r"document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)", "dom_xss_source_document"),
    (r"location\.(href|search|hash|pathname|protocol|host|hostname|assign|replace)", "dom_xss_source_location"),
    (r"window\.name", "dom_xss_source_window_name"),
    (r"(localStorage|sessionStorage)\.(getItem|setItem)", "dom_xss_storage_manipulation"),
    (r"document\.write\(|document\.writeln\(", "dom_xss_sink_document_write"),
    (r"document\.domain", "dom_xss_sink_document_domain"),
    (r"\.innerHTML\s*=", "dom_xss_sink_innerHTML"),
    (r"\.outerHTML\s*=", "dom_xss_sink_outerHTML"),
    (r"\.insertAdjacentHTML\s*\(", "dom_xss_sink_insertAdjacentHTML"),
    (r"\.setAttribute\s*\(\s*['\"](?:on\w+|href|src|action)", "dom_xss_sink_setAttribute"),
    (r"\.(src|href|action)\s*=\s*['\"]?javascript:", "dom_xss_sink_js_protocol"),
    (r"eval\s*\(|Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]", "dom_xss_sink_eval"),
    (r"range\.createContextualFragment\(", "dom_xss_sink_createContextualFragment"),
    (r"execCommand\s*\(|execScript\s*\(", "dom_xss_sink_execCommand"),
    (r"XMLHttpRequest\.(open|send|setRequestHeader)\(", "dom_xss_xhr_manipulation"),
    (r"jQuery\.(ajax|globalEval|parseHTML)\(|\$\.(ajax|globalEval|parseHTML)\(", "dom_xss_jquery_sinks"),
    (r"JSON\.parse\(|jQuery\.parseJSON\(|\$\s*\.\s*parseJSON\(", "dom_xss_json_injection"),
    (r"WebSocket\s*\(\s*['\"]", "dom_xss_websocket_poisoning"),
    (r"postMessage\s*\(", "dom_xss_webmessage_manipulation"),
    (r"document\.evaluate\(", "dom_xss_xpath_injection"),
    (r"executeSql\s*\(", "dom_xss_client_sql_injection"),
    (r"history\.(pushState|replaceState)\s*\(", "dom_xss_history_manipulation"),
    (r"requestFileSystem\s*\(", "dom_xss_dos_filesystem"),
    (r"RegExp\s*\(\s*['\"]", "dom_xss_dos_regex"),
    (r"<iframe[^>]*name\s*=\s*['\"]", "dom_clobbering_iframe_name"),
    (r"window\.open\s*\([^,]+,\s*['\"]", "dom_clobbering_window_open"),
    (r"domElem\.srcdoc\s*=", "dom_xss_sink_srcdoc"),
    (r"\.onevent\s*=\s*['\"]?", "dom_xss_sink_event_handler"),
    (r"\.backgroundImage\s*=\s*['\"]?url\s*\(\s*['\"]?javascript:", "dom_xss_sink_backgroundImage"),
    (r"\.codebase\s*=\s*['\"]", "dom_xss_sink_codebase"),
]

CATEGORY_CONFIG_KEYS = {
    "SQL Injection": "sql_injection",
    "XSS": "xss",
    "DOM XSS": "dom_xss",
    "SSTI": "ssti",
    "SSI": "ssi",
    "XXE/XML": "xxe_xml",
    "Command Injection": "command_injection",
    "File Inclusion": "file_inclusion",
    "File Upload": "file_upload",
}

ALL_PATTERN_CATEGORIES = [
    ("SQL Injection", SQL_INJECTION_PATTERNS, ThreatLevel.HIGH),
    ("XSS", XSS_PATTERNS, ThreatLevel.MEDIUM),
    ("DOM XSS", DOM_XSS_SOURCE_SINK_PATTERNS, ThreatLevel.HIGH),
    ("SSTI", SSTI_PATTERNS, ThreatLevel.HIGH),
    ("SSI", SSI_PATTERNS, ThreatLevel.MEDIUM),
    ("XXE/XML", XXE_XML_PATTERNS, ThreatLevel.CRITICAL),
    ("Command Injection", COMMAND_INJECTION_PATTERNS, ThreatLevel.CRITICAL),
    ("File Inclusion", FILE_INCLUSION_PATTERNS, ThreatLevel.HIGH),
    ("File Upload", FILE_UPLOAD_PATTERNS, ThreatLevel.HIGH),
]


class SignatureStrategy(Strategy):
    name = "signature"

    def __init__(self):
        self.patterns = ALL_PATTERN_CATEGORIES

    async def evaluate(self, request: RequestMetadata) -> AIStrategyResult:
        matched_patterns = []
        highest_threat = ThreatLevel.NONE

        content_to_check = " ".join([
            request.path,
            request.query_string,
            request.body_preview,
        ]).lower()

        for category, patterns, _ in self.patterns:
            config_key = CATEGORY_CONFIG_KEYS.get(category, category.lower().replace(" ", "_"))
            if not waf_config.is_category_enabled("signature", config_key):
                continue
            for pattern, pattern_name in patterns:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    matched_patterns.append(f"{category}: {pattern_name}")
                    threat = self._get_threat_for_category(category)
                    if self._threat_weight(threat) > self._threat_weight(highest_threat):
                        highest_threat = threat

        if matched_patterns:
            decision = Decision.BLOCK
            reason = f"Detected {len(matched_patterns)} malicious pattern(s)"
        else:
            decision = Decision.ALLOW
            reason = "No malicious patterns detected"

        confidence = min(0.95, 0.5 + (len(matched_patterns) * 0.15)) if matched_patterns else 0.9

        return AIStrategyResult(
            strategy_name=self.name,
            decision=decision,
            threat_level=highest_threat,
            confidence=confidence,
            reason=reason,
            matched_patterns=matched_patterns
        )

    def _get_threat_for_category(self, category: str) -> ThreatLevel:
        threats = {
            "SQL Injection": ThreatLevel.HIGH,
            "XSS": ThreatLevel.MEDIUM,
            "DOM XSS": ThreatLevel.HIGH,
            "SSTI": ThreatLevel.HIGH,
            "SSI": ThreatLevel.MEDIUM,
            "XXE/XML": ThreatLevel.CRITICAL,
            "Command Injection": ThreatLevel.CRITICAL,
            "File Inclusion": ThreatLevel.HIGH,
            "File Upload": ThreatLevel.HIGH,
            "Path Traversal": ThreatLevel.HIGH,
        }
        return threats.get(category, ThreatLevel.LOW)

    def _threat_weight(self, threat: ThreatLevel) -> int:
        weights = {
            ThreatLevel.NONE: 0,
            ThreatLevel.LOW: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.HIGH: 3,
            ThreatLevel.CRITICAL: 4,
        }
        return weights.get(threat, 0)
