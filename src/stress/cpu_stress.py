"""
CPU Stress Test Module

Performs intensive CPU workload to stress test all cores.
Monitors temperature and utilization during the test.
"""

import multiprocessing
import time
import math
import psutil
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class CPUStressResult:
    """Results from CPU stress test."""
    duration_seconds: int
    cores_tested: int
    max_temperature: Optional[float] = None
    avg_temperature: Optional[float] = None
    max_utilization: float = 0.0
    avg_utilization: float = 0.0
    min_frequency: float = 0.0
    max_frequency: float = 0.0
    avg_frequency: float = 0.0
    throttling_detected: bool = False
    samples: List[Dict] = field(default_factory=list)
    passed: bool = True
    error: Optional[str] = None


def _stress_worker(stop_event: multiprocessing.Event):
    """
    Worker function that performs CPU-intensive calculations.
    Runs until stop_event is set.
    """
    while not stop_event.is_set():
        # Heavy math operations to stress CPU
        for _ in range(10000):
            x = 123456.789
            x = math.sqrt(x)
            x = math.sin(x) * math.cos(x)
            x = math.log(abs(x) + 1)
            x = x ** 2.5

            # Prime number calculation (CPU intensive)
            n = 997
            for i in range(2, int(math.sqrt(n)) + 1):
                if n % i == 0:
                    break


def _get_cpu_temp() -> Optional[float]:
    """Get CPU temperature using psutil or WMI fallback."""
    try:
        temps = psutil.sensors_temperatures()
        if temps:
            for name, entries in temps.items():
                if 'cpu' in name.lower() or 'core' in name.lower():
                    if entries:
                        return entries[0].current
            # Try any available sensor
            for name, entries in temps.items():
                if entries:
                    return entries[0].current
    except Exception:
        pass

    # WMI fallback for Windows
    try:
        import wmi
        w = wmi.WMI(namespace="root\\WMI")
        temp_info = w.MSAcpi_ThermalZoneTemperature()
        if temp_info:
            # Convert from deciKelvin to Celsius
            kelvin = temp_info[0].CurrentTemperature / 10.0
            return kelvin - 273.15
    except Exception:
        pass

    return None


class CPUStressTest:
    """CPU Stress Test that loads all cores with intensive calculations."""

    def __init__(self):
        self.cpu_count = psutil.cpu_count(logical=True) or 4
        self.processes: List[multiprocessing.Process] = []
        self.stop_event: Optional[multiprocessing.Event] = None
        self.running = False

    def run(
        self,
        duration: int = 60,
        cores: Optional[int] = None,
        progress_callback: Optional[Callable[[int, Dict], None]] = None
    ) -> CPUStressResult:
        """
        Run CPU stress test.

        Args:
            duration: Test duration in seconds (default 60)
            cores: Number of cores to stress (default: all)
            progress_callback: Called each second with (elapsed_seconds, current_stats)

        Returns:
            CPUStressResult with test results
        """
        cores_to_use = cores or self.cpu_count
        result = CPUStressResult(
            duration_seconds=duration,
            cores_tested=cores_to_use
        )

        temperatures: List[float] = []
        utilizations: List[float] = []
        frequencies: List[float] = []

        try:
            # Create stop event and worker processes
            self.stop_event = multiprocessing.Event()
            self.processes = []

            # Start worker processes for each core
            for _ in range(cores_to_use):
                p = multiprocessing.Process(target=_stress_worker, args=(self.stop_event,))
                p.start()
                self.processes.append(p)

            self.running = True
            start_time = time.time()

            # Monitor while stress test runs
            for elapsed in range(duration):
                if not self.running:
                    break

                time.sleep(1)

                # Collect metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                cpu_freq = psutil.cpu_freq()
                cpu_temp = _get_cpu_temp()

                current_freq = cpu_freq.current if cpu_freq else 0

                utilizations.append(cpu_percent)
                frequencies.append(current_freq)
                if cpu_temp is not None:
                    temperatures.append(cpu_temp)

                # Build sample data
                sample = {
                    'elapsed': elapsed + 1,
                    'utilization': cpu_percent,
                    'frequency': current_freq,
                    'temperature': cpu_temp
                }
                result.samples.append(sample)

                # Call progress callback
                if progress_callback:
                    progress_callback(elapsed + 1, sample)

                # Check for throttling (frequency drop > 10%)
                if frequencies and current_freq < frequencies[0] * 0.9:
                    result.throttling_detected = True

            # Stop workers
            self.stop_event.set()
            for p in self.processes:
                p.join(timeout=2)
                if p.is_alive():
                    p.terminate()

            self.running = False

            # Calculate results
            if utilizations:
                result.max_utilization = max(utilizations)
                result.avg_utilization = sum(utilizations) / len(utilizations)

            if frequencies:
                result.min_frequency = min(frequencies)
                result.max_frequency = max(frequencies)
                result.avg_frequency = sum(frequencies) / len(frequencies)

            if temperatures:
                result.max_temperature = max(temperatures)
                result.avg_temperature = sum(temperatures) / len(temperatures)

                # Check for thermal issues
                if result.max_temperature > 95:
                    result.passed = False
                    result.error = f"Critical temperature reached: {result.max_temperature:.1f}C"

        except Exception as e:
            result.passed = False
            result.error = str(e)
            self.stop()

        return result

    def stop(self):
        """Stop the stress test."""
        self.running = False
        if self.stop_event:
            self.stop_event.set()

        for p in self.processes:
            if p.is_alive():
                p.terminate()

        self.processes = []
