"""GPU Scanner - Graphics card information and health."""
from typing import List, Optional

from ...core.scanner import BaseScanner
from ...core.result import ScanResult, Finding, Severity
from ...utils.wmi_helper import wmi_query


class GPUScanner(BaseScanner):
    """Scan GPU information and health status."""

    name = "GPU"
    category = "hardware"
    description = "Graphics card information"
    requires_admin = False

    def scan(self) -> ScanResult:
        findings: List[Finding] = []
        raw_data = {"gpus": []}

        try:
            # Try NVIDIA first
            nvidia_gpus = self._get_nvidia_gpus()
            if nvidia_gpus:
                raw_data["gpus"].extend(nvidia_gpus)

            # Get all GPUs from WMI (includes AMD, Intel, etc.)
            wmi_gpus = self._get_wmi_gpus()

            # Add non-NVIDIA GPUs from WMI
            nvidia_names = [g["name"].lower() for g in nvidia_gpus]
            for gpu in wmi_gpus:
                if gpu["name"].lower() not in nvidia_names:
                    raw_data["gpus"].append(gpu)

            # Build findings
            for gpu in raw_data["gpus"]:
                name = gpu.get("name", "Unknown GPU")
                vram = gpu.get("vram_mb", 0)
                vram_str = f"{vram / 1024:.1f} GB" if vram >= 1024 else f"{vram} MB"
                driver = gpu.get("driver_version", "Unknown")
                temp = gpu.get("temperature_celsius")

                temp_str = f" - {temp:.0f}°C" if temp else ""
                severity = Severity.PASS

                # Check temperature
                if temp:
                    if temp > 90:
                        severity = Severity.CRITICAL
                        findings.append(self._finding(
                            title=f"Critical GPU temperature: {name}",
                            description=f"Temperature is {temp:.0f}°C",
                            severity=Severity.CRITICAL,
                            recommendation="Check GPU cooling immediately"
                        ))
                    elif temp > 80:
                        severity = Severity.WARNING
                        findings.append(self._finding(
                            title=f"High GPU temperature: {name}",
                            description=f"Temperature is {temp:.0f}°C",
                            severity=Severity.WARNING,
                            recommendation="Monitor GPU cooling"
                        ))

                findings.append(self._finding(
                    title=f"{name}",
                    description=f"VRAM: {vram_str}, Driver: {driver}{temp_str}",
                    severity=severity if severity != Severity.PASS else Severity.PASS
                ))

            if not raw_data["gpus"]:
                findings.append(self._finding(
                    title="No GPU detected",
                    description="Could not detect any graphics adapter",
                    severity=Severity.WARNING
                ))

            return self._create_result(findings=findings, raw_data=raw_data)

        except Exception as e:
            return self._create_result(success=False, error=str(e))

    def _get_nvidia_gpus(self) -> List[dict]:
        """Get NVIDIA GPU info using pynvml."""
        gpus = []
        try:
            import pynvml
            pynvml.nvmlInit()

            device_count = pynvml.nvmlDeviceGetCount()
            for i in range(device_count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(i)

                name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode('utf-8')

                memory = pynvml.nvmlDeviceGetMemoryInfo(handle)

                try:
                    temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
                except Exception:
                    temp = None

                try:
                    driver = pynvml.nvmlSystemGetDriverVersion()
                    if isinstance(driver, bytes):
                        driver = driver.decode('utf-8')
                except Exception:
                    driver = "Unknown"

                try:
                    utilization = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    gpu_util = utilization.gpu
                    mem_util = utilization.memory
                except Exception:
                    gpu_util = None
                    mem_util = None

                gpus.append({
                    "name": name,
                    "manufacturer": "NVIDIA",
                    "vram_mb": memory.total // (1024 * 1024),
                    "vram_used_mb": memory.used // (1024 * 1024),
                    "vram_free_mb": memory.free // (1024 * 1024),
                    "driver_version": driver,
                    "temperature_celsius": temp,
                    "gpu_utilization": gpu_util,
                    "memory_utilization": mem_util,
                    "is_nvidia": True
                })

            pynvml.nvmlShutdown()
        except ImportError:
            pass
        except Exception:
            pass

        return gpus

    def _get_wmi_gpus(self) -> List[dict]:
        """Get GPU info from WMI."""
        gpus = []
        try:
            gpu_info = wmi_query("Win32_VideoController")
            for gpu in gpu_info:
                name = gpu.get("Name", "Unknown")
                adapter_ram = gpu.get("AdapterRAM", 0)

                # AdapterRAM can be negative due to int32 overflow for >2GB
                if adapter_ram and adapter_ram > 0:
                    vram_mb = adapter_ram // (1024 * 1024)
                else:
                    # Try to get from dedicated video memory
                    vram_mb = 0

                gpus.append({
                    "name": name,
                    "manufacturer": gpu.get("AdapterCompatibility", "Unknown"),
                    "vram_mb": vram_mb,
                    "driver_version": gpu.get("DriverVersion", "Unknown"),
                    "driver_date": gpu.get("DriverDate", "Unknown"),
                    "status": gpu.get("Status", "Unknown"),
                    "is_nvidia": "nvidia" in name.lower(),
                    "is_amd": "amd" in name.lower() or "radeon" in name.lower(),
                    "is_intel": "intel" in name.lower()
                })
        except Exception:
            pass

        return gpus
