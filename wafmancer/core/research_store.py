"""
Research Data Persistence Layer
===============================
Stores all Oracle session data in structured SQLite format
for publication-ready research analysis.

Enables:
- Reproducible research
- WAF evolution tracking over time
- Cross-target analysis
- Publication-ready data export
"""

import json
import sqlite3
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from wafmancer.config import config
from wafmancer.core.oracle import OracleSession, ProbeResult
from wafmancer.core.diff_engine import AnomalySeverity, DiffResult

logger = structlog.get_logger(__name__)

DB_SCHEMA = """
-- Research sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    waf_vendor TEXT,
    waf_confidence REAL,
    waf_evidence TEXT,  -- JSON array
    total_probes INTEGER DEFAULT 0,
    anomalies_found INTEGER DEFAULT 0,
    bypass_count INTEGER DEFAULT 0,
    high_severity_count INTEGER DEFAULT 0,
    baseline_status INTEGER,
    baseline_length INTEGER,
    baseline_server TEXT,
    session_data TEXT  -- Full JSON dump for reproducibility
);

-- Individual probe records
CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    mutation_name TEXT NOT NULL,
    request_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    method TEXT,
    url TEXT,
    request_headers TEXT,  -- JSON
    request_body BLOB,
    status_code INTEGER,
    response_headers TEXT,  -- JSON
    response_body BLOB,
    response_length INTEGER,
    elapsed_seconds REAL,
    is_anomaly BOOLEAN DEFAULT 0,
    is_bypass BOOLEAN DEFAULT 0,
    severity TEXT,
    anomaly_details TEXT,  -- JSON
    research_notes TEXT,  -- JSON
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- WAF fingerprint history
CREATE TABLE IF NOT EXISTS waf_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    vendor TEXT NOT NULL,
    confidence REAL,
    evidence TEXT,  -- JSON
    known_vulnerabilities TEXT,  -- JSON
    suggested_mutations TEXT,  -- JSON
    fingerprint_date TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Findings index (for quick cross-session research)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    description TEXT NOT NULL,
    mutation_name TEXT,
    is_exploitable BOOLEAN DEFAULT 0,
    discovery_date TEXT NOT NULL,
    waf_vendor TEXT,
    cve_candidate BOOLEAN DEFAULT 0,
    tags TEXT,  -- JSON array
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_probes_session ON probes(session_id);
CREATE INDEX IF NOT EXISTS idx_probes_severity ON probes(severity);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_vendor ON findings(waf_vendor);
CREATE INDEX IF NOT EXISTS idx_sessions_target ON sessions(target);
CREATE INDEX IF NOT EXISTS idx_sessions_date ON sessions(start_time);
"""


class ResearchStore:
    """
    Persistent storage for WAFMANCER research data.
    Uses SQLite for portability and easy sharing of research databases.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        """
        Initialize the research data store.

        Args:
            db_path: Path to SQLite database file (default: data/research.db)
        """
        if db_path is None:
            db_path = Path(config.get("output", "data_dir", default="data")) / "research.db"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._conn: Optional[sqlite3.Connection] = None
        self._initialize_database()

        logger.info("research_store_initialized", db_path=str(self.db_path))

    def _initialize_database(self) -> None:
        """Create database schema if it doesn't exist."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript(DB_SCHEMA)
            conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection (create if needed)."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def save_session(self, session: OracleSession) -> int:
        """
        Save an entire Oracle session to the database.

        Args:
            session: Complete OracleSession with all data

        Returns:
            Session ID in the database
        """
        conn = self._get_connection()
        end_time = datetime.now(timezone.utc).isoformat()

        # Extract WAF info
        waf_vendor = None
        waf_confidence = None
        waf_evidence = None

        if session.waf_fingerprint:
            waf_vendor = session.waf_fingerprint.vendor.value
            waf_confidence = session.waf_fingerprint.confidence
            waf_evidence = json.dumps(session.waf_fingerprint.evidence)

        stats = session.statistics

        # Insert session record
        cursor = conn.execute(
            """INSERT INTO sessions 
               (target, start_time, end_time, waf_vendor, waf_confidence, 
                waf_evidence, total_probes, anomalies_found, bypass_count,
                high_severity_count, baseline_status, baseline_length,
                baseline_server, session_data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session.target,
                session.start_time,
                end_time,
                waf_vendor,
                waf_confidence,
                waf_evidence,
                stats.get("total_probes", 0),
                stats.get("anomalies_found", 0),
                stats.get("bypass_count", 0),
                stats.get("high_severity_count", 0),
                session.baseline.response.status_code if session.baseline else None,
                session.baseline.response.body_length if session.baseline else None,
                session.baseline.response.server_header if session.baseline else None,
                json.dumps(self._serialize_session(session)),
            ),
        )
        session_id = cursor.lastrowid

        # Save WAF fingerprint
        if session.waf_fingerprint:
            self._save_fingerprint(conn, session_id, session.waf_fingerprint)

        # Save individual probes
        if session.probes:
            self._save_probes(conn, session_id, session.probes)

        # Save findings
        if session.anomalies:
            self._save_findings(conn, session_id, session.anomalies, waf_vendor)

        conn.commit()

        logger.info(
            "session_saved",
            session_id=session_id,
            target=session.target,
            probes_saved=len(session.probes),
            anomalies_saved=len(session.anomalies),
        )

        return session_id

    def _save_fingerprint(
        self, conn: sqlite3.Connection, session_id: int, fingerprint
    ) -> None:
        """Save WAF fingerprint data."""
        conn.execute(
            """INSERT INTO waf_fingerprints
               (session_id, vendor, confidence, evidence, 
                known_vulnerabilities, suggested_mutations, fingerprint_date)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                fingerprint.vendor.value,
                fingerprint.confidence,
                json.dumps(fingerprint.evidence),
                json.dumps(fingerprint.known_vulnerabilities),
                json.dumps(fingerprint.suggested_mutations),
                datetime.now(timezone.utc).isoformat(),
            ),
        )

    def _save_probes(
        self, conn: sqlite3.Connection, session_id: int, probes: List[ProbeResult]
    ) -> None:
        """Save all probe results."""
        for probe in probes:
            severity = None
            anomaly_details = None
            research_notes = None
            is_anomaly = 0
            is_bypass = 0

            if probe.diff:
                severity = probe.diff.severity.name
                anomaly_details = json.dumps(probe.diff.anomalies)
                research_notes = json.dumps(probe.diff.research_notes)
                is_anomaly = 1 if probe.is_anomaly else 0
                is_bypass = 1 if probe.is_bypass else 0

            conn.execute(
                """INSERT INTO probes
                   (session_id, mutation_name, request_id, timestamp,
                    method, url, request_headers, request_body,
                    status_code, response_headers, response_body,
                    response_length, elapsed_seconds,
                    is_anomaly, is_bypass, severity,
                    anomaly_details, research_notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    f"Probe-{probe.request.request_id[:8]}",
                    probe.request.request_id,
                    probe.request.timestamp or datetime.now(timezone.utc).isoformat(),
                    probe.request.method,
                    probe.request.url,
                    json.dumps(probe.request.headers),
                    probe.request.body,
                    probe.response.status_code,
                    json.dumps(probe.response.headers),
                    probe.response.body,
                    probe.response.body_length,
                    probe.response.elapsed_seconds,
                    is_anomaly,
                    is_bypass,
                    severity,
                    anomaly_details,
                    research_notes,
                ),
            )

    def _save_findings(
        self,
        conn: sqlite3.Connection,
        session_id: int,
        anomalies: List[DiffResult],
        waf_vendor: Optional[str],
    ) -> None:
        """Extract and save individual findings from anomalies."""
        for anomaly in anomalies:
            if anomaly.severity == AnomalySeverity.NONE:
                continue

            # Determine finding type from anomalies
            finding_type = self._classify_finding(anomaly)
            description = "; ".join(anomaly.anomalies) if anomaly.anomalies else "Anomaly detected"

            # Determine if this could be a CVE candidate
            cve_candidate = (
                anomaly.severity in (AnomalySeverity.HIGH, AnomalySeverity.CRITICAL)
                and anomaly.is_exploitable
            )

            # Generate tags
            tags = self._generate_tags(anomaly, waf_vendor)

            conn.execute(
                """INSERT INTO findings
                   (session_id, severity, finding_type, description,
                    is_exploitable, discovery_date, waf_vendor,
                    cve_candidate, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    anomaly.severity.name,
                    finding_type,
                    description,
                    1 if anomaly.is_exploitable else 0,
                    datetime.now(timezone.utc).isoformat(),
                    waf_vendor,
                    1 if cve_candidate else 0,
                    json.dumps(tags),
                ),
            )

    def _classify_finding(self, anomaly: DiffResult) -> str:
        """Classify the type of finding from anomaly data."""
        anomaly_text = " ".join(anomaly.anomalies).lower()

        if "waf block" in anomaly_text:
            return "waf_detection"
        elif "bypass" in anomaly_text:
            return "potential_bypass"
        elif "smuggling" in anomaly_text or "transfer-encoding" in anomaly_text:
            return "request_smuggling"
        elif "header" in anomaly_text:
            return "header_manipulation"
        elif "timing" in anomaly_text:
            return "timing_side_channel"
        elif "entropy" in anomaly_text:
            return "response_manipulation"
        elif "status code" in anomaly_text:
            return "status_code_deviation"
        else:
            return "unknown_anomaly"

    def _generate_tags(self, anomaly: DiffResult, waf_vendor: Optional[str]) -> List[str]:
        """Generate searchable tags for a finding."""
        tags = []

        if waf_vendor:
            tags.append(f"waf:{waf_vendor.lower().replace(' ', '_')}")

        tags.append(f"severity:{anomaly.severity.name.lower()}")

        if anomaly.is_exploitable:
            tags.append("exploitable")

        if "waf block" in " ".join(anomaly.anomalies).lower():
            tags.append("waf_interaction")

        return tags

    def _serialize_session(self, session: OracleSession) -> Dict[str, Any]:
        """Serialize an OracleSession to a JSON-safe dictionary."""
        data = {
            "target": session.target,
            "start_time": session.start_time,
            "statistics": session.statistics,
        }

        if session.baseline:
            data["baseline"] = {
                "status": session.baseline.response.status_code,
                "length": session.baseline.response.body_length,
                "server": session.baseline.response.server_header,
            }

        if session.waf_fingerprint:
            data["waf_fingerprint"] = {
                "vendor": session.waf_fingerprint.vendor.value,
                "confidence": session.waf_fingerprint.confidence,
            }

        return data

    def query_findings(
        self,
        severity: Optional[str] = None,
        vendor: Optional[str] = None,
        exploitable_only: bool = False,
        cve_candidates_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Query the findings database with filters.

        Args:
            severity: Filter by severity level
            vendor: Filter by WAF vendor
            exploitable_only: Only show exploitable findings
            cve_candidates_only: Only show potential CVE candidates
            limit: Maximum results

        Returns:
            List of finding dictionaries
        """
        conn = self._get_connection()

        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())

        if vendor:
            query += " AND waf_vendor = ?"
            params.append(vendor)

        if exploitable_only:
            query += " AND is_exploitable = 1"

        if cve_candidates_only:
            query += " AND cve_candidate = 1"

        query += " ORDER BY discovery_date DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_session_history(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get historical session data, optionally filtered by target.

        Args:
            target: Optional target filter

        Returns:
            List of session summaries
        """
        conn = self._get_connection()

        if target:
            cursor = conn.execute(
                """SELECT id, target, start_time, end_time, waf_vendor,
                          total_probes, anomalies_found, bypass_count
                   FROM sessions
                   WHERE target = ?
                   ORDER BY start_time DESC""",
                (target,),
            )
        else:
            cursor = conn.execute(
                """SELECT id, target, start_time, end_time, waf_vendor,
                          total_probes, anomalies_found, bypass_count
                   FROM sessions
                   ORDER BY start_time DESC
                   LIMIT 50"""
            )

        return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregate statistics across all research sessions."""
        conn = self._get_connection()

        stats = {}

        # Total sessions
        cursor = conn.execute("SELECT COUNT(*) as count FROM sessions")
        stats["total_sessions"] = cursor.fetchone()["count"]

        # Total probes
        cursor = conn.execute("SELECT COUNT(*) as count FROM probes")
        stats["total_probes"] = cursor.fetchone()["count"]

        # Findings by severity
        cursor = conn.execute(
            """SELECT severity, COUNT(*) as count 
               FROM findings 
               GROUP BY severity 
               ORDER BY count DESC"""
        )
        stats["findings_by_severity"] = {
            row["severity"]: row["count"] for row in cursor.fetchall()
        }

        # Top WAF vendors
        cursor = conn.execute(
            """SELECT waf_vendor, COUNT(*) as count 
               FROM sessions 
               WHERE waf_vendor IS NOT NULL
               GROUP BY waf_vendor 
               ORDER BY count DESC 
               LIMIT 10"""
        )
        stats["top_wafs"] = {
            row["waf_vendor"]: row["count"] for row in cursor.fetchall()
        }

        # Exploitable findings
        cursor = conn.execute(
            "SELECT COUNT(*) as count FROM findings WHERE is_exploitable = 1"
        )
        stats["exploitable_findings"] = cursor.fetchone()["count"]

        # CVE candidates
        cursor = conn.execute(
            "SELECT COUNT(*) as count FROM findings WHERE cve_candidate = 1"
        )
        stats["cve_candidates"] = cursor.fetchone()["count"]

        return stats

    def export_findings_markdown(self, output_path: Path) -> None:
        """Export all findings to a publication-ready markdown file."""
        findings = self.query_findings(limit=1000)

        # Group by severity
        grouped: Dict[str, List[Dict]] = {}
        for finding in findings:
            severity = finding["severity"]
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(finding)

        # Generate markdown
        lines = [
            "# WAFMANCER Research Findings Database",
            f"\n**Export Date:** {datetime.now(timezone.utc).isoformat()}",
            f"**Total Findings:** {len(findings)}",
            "\n---\n",
        ]

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for severity in severity_order:
            if severity in grouped:
                lines.append(f"## {severity} Severity Findings\n")
                for f in grouped[severity]:
                    lines.append(f"### Finding {f['id']}")
                    lines.append(f"- **Type:** {f['finding_type']}")
                    lines.append(f"- **WAF:** {f.get('waf_vendor', 'Unknown')}")
                    lines.append(f"- **Description:** {f['description']}")
                    lines.append(f"- **Exploitable:** {'Yes ⚠️' if f['is_exploitable'] else 'No'}")
                    lines.append(f"- **CVE Candidate:** {'Yes 🔥' if f['cve_candidate'] else 'No'}")
                    if f.get("tags"):
                        tags = json.loads(f["tags"])
                        lines.append(f"- **Tags:** {', '.join(tags)}")
                    lines.append(f"- **Discovered:** {f['discovery_date']}")
                    lines.append("")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines))

        logger.info("findings_exported", path=str(output_path), count=len(findings))

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
