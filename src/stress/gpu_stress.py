"""
GPU Stress Test Module

Performs intensive GPU workload using OpenCL compute operations.
Monitors temperature, utilization, and VRAM during the test.
"""

import time
import threading
import numpy as np
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field


# OpenCL kernel for GPU stress - runs heavy math on millions of GPU threads
OPENCL_STRESS_KERNEL = """
__kernel void gpu_stress(__global float *data, const int iterations) {
    int gid = get_global_id(0);
    float x = data[gid];

    // Heavy math loop to stress GPU compute units
    for (int i = 0; i < iterations; i++) {
        x = sin(x) * cos(x) + sqrt(fabs(x) + 0.001f);
        x = pow(fabs(x) + 0.001f, 1.5f) + log(fabs(x) + 1.0f);
        x = tan(x * 0.01f) + exp(fabs(x) * 0.001f);
        x = x * x - floor(x);
    }

    data[gid] = x;
}
"""


@dataclass
class GPUStressResult:
    """Results from GPU stress test."""
    duration_seconds: int
    gpu_name: str = "Unknown"
    max_temperature: Optional[float] = None
    avg_temperature: Optional[float] = None
    max_utilization: float = 0.0
    avg_utilization: float = 0.0
    max_memory_used_mb: float = 0.0
    total_memory_mb: float = 0.0
    throttling_detected: bool = False
    opencl_used: bool = False
    samples: List[Dict] = field(default_factory=list)
    passed: bool = True
    error: Optional[str] = None


def _get_nvidia_gpu_stats() -> Optional[Dict]:
    """Get NVIDIA GPU stats using pynvml."""
    try:
        import pynvml
        pynvml.nvmlInit()

        device_count = pynvml.nvmlDeviceGetCount()
        if device_count == 0:
            pynvml.nvmlShutdown()
            return None

        handle = pynvml.nvmlDeviceGetHandleByIndex(0)

        name = pynvml.nvmlDeviceGetName(handle)
        if isinstance(name, bytes):
            name = name.decode('utf-8')

        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)

        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        gpu_util = util.gpu

        mem_info = pynvml.nvmlDeviceGetMemoryInfo(handle)
        mem_used_mb = mem_info.used / (1024 * 1024)
        mem_total_mb = mem_info.total / (1024 * 1024)

        pynvml.nvmlShutdown()

        return {
            'name': name,
            'temperature': temp,
            'utilization': gpu_util,
            'memory_used_mb': mem_used_mb,
            'memory_total_mb': mem_total_mb
        }
    except Exception:
        return None


def _get_gpu_stats_wmi() -> Optional[Dict]:
    """Get GPU stats using WMI (fallback for non-NVIDIA)."""
    try:
        import wmi
        w = wmi.WMI()
        gpus = w.Win32_VideoController()
        if gpus:
            gpu = gpus[0]
            adapter_ram = getattr(gpu, 'AdapterRAM', 0) or 0
            if adapter_ram < 0:
                adapter_ram = 4 * 1024 * 1024 * 1024

            return {
                'name': gpu.Name or "Unknown GPU",
                'temperature': None,
                'utilization': None,
                'memory_used_mb': None,
                'memory_total_mb': adapter_ram / (1024 * 1024)
            }
    except Exception:
        pass
    return None


class GPUStressTest:
    """GPU Stress Test using OpenCL compute operations."""

    def __init__(self):
        self.running = False
        self.stress_thread: Optional[threading.Thread] = None
        self._stop_flag = False
        self._opencl_available = False
        self._cl_context = None
        self._cl_queue = None
        self._cl_program = None

        # Try to initialize OpenCL
        self._init_opencl()

    def _init_opencl(self):
        """Initialize OpenCL context and compile kernel."""
        try:
            import pyopencl as cl

            # Get all available platforms and devices
            platforms = cl.get_platforms()
            if not platforms:
                return

            # Try to find a GPU device
            gpu_device = None
            for platform in platforms:
                try:
                    devices = platform.get_devices(device_type=cl.device_type.GPU)
                    if devices:
                        gpu_device = devices[0]
                        break
                except cl.RuntimeError:
                    continue

            if not gpu_device:
                return

            # Create context and command queue
            self._cl_context = cl.Context([gpu_device])
            self._cl_queue = cl.CommandQueue(self._cl_context)

            # Compile the stress kernel
            self._cl_program = cl.Program(self._cl_context, OPENCL_STRESS_KERNEL).build()

            self._opencl_available = True

        except ImportError:
            pass
        except Exception:
            pass

    def _opencl_stress_worker(self):
        """Worker that performs real GPU compute stress via OpenCL."""
        try:
            import pyopencl as cl

            # Allocate large buffer on GPU (use ~500MB of VRAM)
            # More work items = more GPU stress
            num_elements = 128 * 1024 * 1024  # 128M floats = 512MB
            iterations = 100  # Math iterations per kernel call

            # Create host data
            host_data = np.random.rand(num_elements).astype(np.float32)

            # Create GPU buffer
            mf = cl.mem_flags
            gpu_buffer = cl.Buffer(
                self._cl_context,
                mf.READ_WRITE | mf.COPY_HOST_PTR,
                hostbuf=host_data
            )

            # Run stress kernel continuously
            while not self._stop_flag:
                # Execute kernel on GPU
                self._cl_program.gpu_stress(
                    self._cl_queue,
                    (num_elements,),  # Global work size
                    None,  # Local work size (auto)
                    gpu_buffer,
                    np.int32(iterations)
                )

                # Wait for completion
                self._cl_queue.finish()

            # Cleanup
            gpu_buffer.release()

        except Exception as e:
            # OpenCL failed, stop gracefully
            pass

    def _numpy_stress_worker(self):
        """Fallback worker using numpy (CPU-based)."""
        try:
            size = 2000
            while not self._stop_flag:
                a = np.random.rand(size, size).astype(np.float32)
                b = np.random.rand(size, size).astype(np.float32)
                c = np.dot(a, b)
                d = np.sin(c) * np.cos(c)
                e = np.sqrt(np.abs(d) + 1)
                _ = np.sum(e)
        except Exception:
            import math
            while not self._stop_flag:
                for _ in range(100000):
                    x = 123456.789
                    for _ in range(100):
                        x = math.sqrt(abs(x)) * math.sin(x)

    def run(
        self,
        duration: int = 60,
        progress_callback: Optional[Callable[[int, Dict], None]] = None
    ) -> GPUStressResult:
        """
        Run GPU stress test.

        Args:
            duration: Test duration in seconds (default 60)
            progress_callback: Called each second with (elapsed_seconds, current_stats)

        Returns:
            GPUStressResult with test results
        """
        result = GPUStressResult(duration_seconds=duration)
        result.opencl_used = self._opencl_available

        temperatures: List[float] = []
        utilizations: List[float] = []
        memory_used: List[float] = []

        # Get initial GPU info
        nvidia_stats = _get_nvidia_gpu_stats()
        wmi_stats = _get_gpu_stats_wmi()

        if nvidia_stats:
            result.gpu_name = nvidia_stats['name']
            result.total_memory_mb = nvidia_stats['memory_total_mb']
        elif wmi_stats:
            result.gpu_name = wmi_stats['name']
            result.total_memory_mb = wmi_stats['memory_total_mb'] or 0

        if not nvidia_stats and not wmi_stats:
            result.passed = False
            result.error = "No GPU detected"
            return result

        try:
            # Start stress worker thread
            self._stop_flag = False

            # Use OpenCL if available, otherwise fall back to numpy
            if self._opencl_available:
                self.stress_thread = threading.Thread(
                    target=self._opencl_stress_worker, daemon=True
                )
            else:
                self.stress_thread = threading.Thread(
                    target=self._numpy_stress_worker, daemon=True
                )

            self.stress_thread.start()
            self.running = True

            # Monitor while stress test runs
            for elapsed in range(duration):
                if not self.running:
                    break

                time.sleep(1)

                # Collect metrics
                stats = _get_nvidia_gpu_stats()

                sample = {
                    'elapsed': elapsed + 1,
                    'temperature': None,
                    'utilization': None,
                    'memory_used_mb': None,
                    'opencl': self._opencl_available
                }

                if stats:
                    if stats['temperature'] is not None:
                        temperatures.append(stats['temperature'])
                        sample['temperature'] = stats['temperature']

                    if stats['utilization'] is not None:
                        utilizations.append(stats['utilization'])
                        sample['utilization'] = stats['utilization']

                    if stats['memory_used_mb'] is not None:
                        memory_used.append(stats['memory_used_mb'])
                        sample['memory_used_mb'] = stats['memory_used_mb']

                result.samples.append(sample)

                # Call progress callback
                if progress_callback:
                    progress_callback(elapsed + 1, sample)

                # Check for dangerous temps
                if sample['temperature'] and sample['temperature'] > 95:
                    result.throttling_detected = True

            # Stop worker
            self._stop_flag = True
            self.running = False

            if self.stress_thread:
                self.stress_thread.join(timeout=2)

            # Calculate results
            if temperatures:
                result.max_temperature = max(temperatures)
                result.avg_temperature = sum(temperatures) / len(temperatures)

                if result.max_temperature > 95:
                    result.passed = False
                    result.error = f"Critical GPU temperature: {result.max_temperature:.1f}C"

            if utilizations:
                result.max_utilization = max(utilizations)
                result.avg_utilization = sum(utilizations) / len(utilizations)

            if memory_used:
                result.max_memory_used_mb = max(memory_used)

        except Exception as e:
            result.passed = False
            result.error = str(e)
            self.stop()

        return result

    def stop(self):
        """Stop the stress test."""
        self.running = False
        self._stop_flag = True

    @property
    def opencl_available(self) -> bool:
        """Check if OpenCL GPU compute is available."""
        return self._opencl_available
