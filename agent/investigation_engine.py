import asyncio, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mcp_server'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'mcp_server', 'utils'))

from logger import log_investigation_step

MALWARE_KEYWORDS = ["mimikatz","psexec","meterpreter","nc.exe","ncat","cobalt","beacon","empire"]
C2_PORTS = [4444, 4445, 1337, 31337, 8888, 9999, 6666]
PERSIST_PATTERNS = ["CurrentVersion\\Run","CurrentVersion\\RunOnce","Winlogon","AppInit_DLLs"]

class InvestigationEngine:
    def __init__(self, mcp_client):
        self.mcp = mcp_client
        self.evidence = {}
        self.timeline = []
        self.iocs = []

    async def investigate(self, image_path: str) -> dict:
        log_investigation_step("START", image_path)
        await self._phase1_triage(image_path)
        if self._has_suspicious_processes():
            await self._phase2_process_deep_dive(image_path)
        if self._has_suspicious_network():
            await self._phase2_network_deep_dive(image_path)
        await self._phase3_cross_validate(image_path)
        self._reconstruct_timeline()
        return self._compile_evidence_package()

    async def _phase1_triage(self, image_path: str):
        log_investigation_step("PHASE1_START", "parallel triage beginning")
        procs, nets = await asyncio.gather(
            self.mcp.get_process_list(image_path),
            self.mcp.get_network_connections(image_path)
        )
        self.evidence["processes"] = procs
        self.evidence["network"] = nets
        log_investigation_step("PHASE1_DONE",
            f"{procs.get('flag_count',0)} suspicious procs, "
            f"{nets.get('flag_count',0)} C2 connections")

    async def _phase2_process_deep_dive(self, image_path: str):
        log_investigation_step("PHASE2_PROCESS", "deep dive triggered")
        persist, modules = await asyncio.gather(
            self.mcp.check_persistence(image_path),
            self.mcp.get_loaded_modules(image_path)
        )
        self.evidence["persistence"] = persist
        self.evidence["modules"] = modules
        for key in persist.get("keys", []):
            if any(p.lower() in key.lower() for p in PERSIST_PATTERNS):
                self.iocs.append({"type":"PERSISTENCE","value":key,"confidence":"HIGH"})

    async def _phase2_network_deep_dive(self, image_path: str):
        log_investigation_step("PHASE2_NETWORK", "network deep dive triggered")
        flagged = self.evidence.get("network", {}).get("flagged", [])
        for c in flagged[:3]:
            ip = c.get("remote_ip", "")
            if ip:
                strings = await self.mcp.search_strings(image_path, ip)
                self.iocs.append({"type":"C2_IP","value":ip,
                    "memory_references":strings.get("count",0),
                    "confidence":"HIGH" if strings.get("count",0)>5 else "MEDIUM"})

    async def _phase3_cross_validate(self, image_path: str):
        log_investigation_step("PHASE3", "cross-validating memory vs disk")
        mft, prefetch = await asyncio.gather(
            self.mcp.extract_mft_timeline(image_path),
            self.mcp.analyze_prefetch(image_path)
        )
        self.evidence["mft"] = mft
        self.evidence["prefetch"] = prefetch

        # Get process NAMES from memory
        mem_procs = self.evidence.get("processes", {}).get("processes", [])
        mem_names = {p["name"].lower() for p in mem_procs if p.get("name")}

        # Get executable NAMES from disk (prefetch)
        disk_exes = prefetch.get("executables", [])
        disk_names = {e["name"].lower() for e in disk_exes if e.get("name")}

        # Ghost processes = in memory but NOT on disk
        # Only flag if name looks suspicious or unknown
        memory_only = mem_names - disk_names

        self.evidence["cross_validation"] = {
            "memory_only_names": list(memory_only),
            "disk_only_names": list(disk_names - mem_names),
            "consistent_names": list(mem_names & disk_names),
            "anomaly_count": len(memory_only)
        }

        for name in memory_only:
            self.iocs.append({
                "type": "GHOST_PROCESS",
                "value": name,
                "confidence": "HIGH",
                "note": "Process name in memory, no matching disk executable found"
            })

        log_investigation_step("PHASE3_DONE",
            f"{len(memory_only)} ghost process names detected")

    def _has_suspicious_processes(self):
        return len(self.evidence.get("processes",{}).get("flagged",[])) > 0

    def _has_suspicious_network(self):
        return len(self.evidence.get("network",{}).get("flagged",[])) > 0

    def _reconstruct_timeline(self):
        events = []
        for entry in self.evidence.get("mft",{}).get("timeline",[]):
            ts = entry.get("timestamp")
            if ts and ts != "UNKNOWN":
                events.append({"time":ts,"source":"DISK_MFT",
                    "event":entry.get("description","")})
        for proc in self.evidence.get("processes",{}).get("flagged",[]):
            events.append({"time":proc.get("create_time","UNKNOWN"),
                "source":"MEMORY",
                "event":f"Malicious process: {proc['name']} PID {proc['pid']}"})
        self.timeline = sorted(
            [e for e in events if e["time"]!="UNKNOWN"],
            key=lambda x: x["time"])

    def _compile_evidence_package(self):
        return {
            "evidence": self.evidence,
            "iocs": self.iocs,
            "attack_timeline": self.timeline,
            "ioc_count": len(self.iocs),
            "phases_completed": list(self.evidence.keys()),
            "summary": {
                "suspicious_processes": len(
                    self.evidence.get("processes",{}).get("flagged",[])),
                "c2_connections": len(
                    self.evidence.get("network",{}).get("flagged",[])),
                "ghost_processes": len(
                    self.evidence.get("cross_validation",{}).get("memory_only_names",[])),
                "persistence_keys": len(
                    self.evidence.get("persistence",{}).get("keys",[]))
            }
        }
