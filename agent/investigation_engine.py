import asyncio
from utils.logger import log_investigation_step

# ── SUSPICION RULES ──────────────────────────────────────────────────────────
MALWARE_KEYWORDS = [
    "mimikatz", "psexec", "meterpreter", "nc.exe",
    "ncat", "cobalt", "beacon", "empire", "powersploit"
]
C2_PORTS = [4444, 4445, 1337, 31337, 8888, 9999, 6666]
PERSIST_PATTERNS = [
    "CurrentVersion\\Run",
    "CurrentVersion\\RunOnce",
    "Winlogon",
    "AppInit_DLLs"
]


class InvestigationEngine:
    """
    Autonomous tool chaining engine — the intelligence layer of Sentinel-MCP.
    Drives the investigation based on evidence signals, not human prompts.
    Encodes real DFIR triage logic: if suspicious process found, check
    persistence next. If C2 traffic found, search memory strings for IOCs.
    """

    def __init__(self, mcp_client):
        self.mcp = mcp_client
        self.evidence = {}
        self.timeline = []
        self.iocs = []

    async def investigate(self, image_path: str) -> dict:
        """
        Entry point — runs full autonomous investigation.
        Returns structured evidence package ready for LLM reasoning.
        """
        log_investigation_step("START", image_path)

        # Phase 1 — Parallel initial triage (always runs)
        await self._phase1_triage(image_path)

        # Phase 2 — Conditional deep dive
        if self._has_suspicious_processes():
            await self._phase2_process_deep_dive(image_path)
        if self._has_suspicious_network():
            await self._phase2_network_deep_dive(image_path)

        # Phase 3 — Cross-validation (memory vs disk)
        await self._phase3_cross_validate(image_path)

        # Phase 4 — Attack timeline reconstruction
        self._reconstruct_timeline()

        return self._compile_evidence_package()

    async def _phase1_triage(self, image_path: str):
        """
        Run process list + network scan in parallel.
        Target: under 60 seconds.
        """
        log_investigation_step("PHASE1_START", "parallel triage beginning")
        procs, nets = await asyncio.gather(
            self.mcp.get_process_list(image_path),
            self.mcp.get_network_connections(image_path)
        )
        self.evidence["processes"] = procs
        self.evidence["network"] = nets
        log_investigation_step(
            "PHASE1_DONE",
            f"{procs.get('flag_count', 0)} suspicious procs, "
            f"{nets.get('flag_count', 0)} C2 connections"
        )

    async def _phase2_process_deep_dive(self, image_path: str):
        """
        Triggered when suspicious processes found in Phase 1.
        Checks persistence + loaded modules in parallel.
        """
        log_investigation_step(
            "PHASE2_PROCESS",
            "deep dive triggered by suspicious process signal"
        )
        persist, modules = await asyncio.gather(
            self.mcp.check_persistence(image_path),
            self.mcp.get_loaded_modules(image_path)
        )
        self.evidence["persistence"] = persist
        self.evidence["modules"] = modules

        for key in persist.get("keys", []):
            if any(p.lower() in key.lower() for p in PERSIST_PATTERNS):
                self.iocs.append({
                    "type": "PERSISTENCE",
                    "value": key,
                    "confidence": "HIGH"
                })

    async def _phase2_network_deep_dive(self, image_path: str):
        """
        Triggered when C2 traffic found in Phase 1.
        Searches memory strings for top 3 suspicious IPs.
        """
        log_investigation_step(
            "PHASE2_NETWORK",
            "deep dive triggered by suspicious network signal"
        )
        flagged = self.evidence.get("network", {}).get("flagged", [])
        suspicious_ips = [c.get("remote_ip", "") for c in flagged[:3]]

        for ip in suspicious_ips:
            if ip:
                strings = await self.mcp.search_strings(image_path, ip)
                self.iocs.append({
                    "type": "C2_IP",
                    "value": ip,
                    "memory_references": strings.get("count", 0),
                    "confidence": "HIGH" if strings.get("count", 0) > 5
                    else "MEDIUM"
                })

    async def _phase3_cross_validate(self, image_path: str):
        """
        Compare memory findings against disk timeline.
        Catches ghost processes (running in memory, no disk trace).
        This is where anti-forensics techniques get detected.
        """
        log_investigation_step(
            "PHASE3",
            "cross-validating memory vs disk artifacts"
        )
        mft, prefetch = await asyncio.gather(
            self.mcp.extract_mft_timeline(image_path),
            self.mcp.analyze_prefetch(image_path)
        )
        self.evidence["mft"] = mft
        self.evidence["prefetch"] = prefetch

        mem_names = {
            p["name"]
            for p in self.evidence.get("processes", {}).get("processes", [])
        }
        disk_names = {
            e["name"]
            for e in prefetch.get("executables", [])
        }

        memory_only = mem_names - disk_names
        disk_only = disk_names - mem_names

        self.evidence["cross_validation"] = {
            "memory_only": list(memory_only),
            "disk_only": list(disk_only),
            "consistent": list(mem_names & disk_names),
            "anomaly_count": len(memory_only)
        }

        for name in memory_only:
            self.iocs.append({
                "type": "GHOST_PROCESS",
                "value": name,
                "confidence": "HIGH",
                "note": "Running in memory, no disk trace — possible injection"
            })

        log_investigation_step(
            "PHASE3_DONE",
            f"{len(memory_only)} ghost processes, "
            f"{len(disk_only)} disk-only artifacts"
        )

    def _has_suspicious_processes(self) -> bool:
        return len(
            self.evidence.get("processes", {}).get("flagged", [])
        ) > 0

    def _has_suspicious_network(self) -> bool:
        return len(
            self.evidence.get("network", {}).get("flagged", [])
        ) > 0

    def _reconstruct_timeline(self):
        """Build ordered attack timeline from all evidence sources."""
        events = []

        for entry in self.evidence.get("mft", {}).get("timeline", []):
            ts = entry.get("timestamp")
            if ts and ts != "UNKNOWN":
                events.append({
                    "time": ts,
                    "source": "DISK_MFT",
                    "event": entry.get("description", "")
                })

        for proc in self.evidence.get("processes", {}).get("flagged", []):
            events.append({
                "time": proc.get("create_time", "UNKNOWN"),
                "source": "MEMORY",
                "event": f"Malicious process: {proc['name']} PID {proc['pid']}"
            })

        self.timeline = sorted(
            [e for e in events if e["time"] != "UNKNOWN"],
            key=lambda x: x["time"]
        )

    def _compile_evidence_package(self) -> dict:
        """Return complete structured evidence package for LLM reasoning."""
        return {
            "evidence": self.evidence,
            "iocs": self.iocs,
            "attack_timeline": self.timeline,
            "ioc_count": len(self.iocs),
            "phases_completed": list(self.evidence.keys()),
            "summary": {
                "suspicious_processes": len(
                    self.evidence.get("processes", {}).get("flagged", [])
                ),
                "c2_connections": len(
                    self.evidence.get("network", {}).get("flagged", [])
                ),
                "ghost_processes": len(
                    self.evidence.get(
                        "cross_validation", {}
                    ).get("memory_only", [])
                ),
                "persistence_keys": len(
                    self.evidence.get("persistence", {}).get("keys", [])
                )
            }
        }