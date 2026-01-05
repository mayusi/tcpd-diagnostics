"""
Memory Stress Test Module

Allocates and tests RAM with various patterns to detect errors.
Monitors memory usage and performance during the test.
"""

import time
import psutil
import random
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class MemoryStressResult:
    """Results from memory stress test."""
    duration_seconds: int
    total_ram_gb: float = 0.0
    tested_ram_gb: float = 0.0
    test_percentage: int = 0
    errors_found: int = 0
    max_usage_percent: float = 0.0
    avg_usage_percent: float = 0.0
    write_speed_mbps: float = 0.0
    read_speed_mbps: float = 0.0
    samples: List[Dict] = field(default_factory=list)
    passed: bool = True
    error: Optional[str] = None


class MemoryStressTest:
    """Memory Stress Test that allocates and verifies RAM."""

    def __init__(self):
        self.running = False
        mem = psutil.virtual_memory()
        self.total_ram = mem.total
        self.available_ram = mem.available

    def run(
        self,
        duration: int = 30,
        percentage: int = 70,
        progress_callback: Optional[Callable[[int, Dict], None]] = None
    ) -> MemoryStressResult:
        """
        Run memory stress test.

        Args:
            duration: Test duration in seconds (default 30)
            percentage: Percentage of available RAM to test (default 70%)
            progress_callback: Called each second with (elapsed_seconds, current_stats)

        Returns:
            MemoryStressResult with test results
        """
        result = MemoryStressResult(
            duration_seconds=duration,
            total_ram_gb=self.total_ram / (1024**3),
            test_percentage=percentage
        )

        usage_samples: List[float] = []
        errors_found = 0

        # Calculate how much RAM to allocate
        mem = psutil.virtual_memory()
        bytes_to_test = int(mem.available * (percentage / 100))
        result.tested_ram_gb = bytes_to_test / (1024**3)

        # Allocate in chunks to avoid single massive allocation
        chunk_size = 100 * 1024 * 1024  # 100 MB chunks
        num_chunks = max(1, bytes_to_test // chunk_size)

        allocated_chunks: List[bytearray] = []

        try:
            self.running = True

            # Phase 1: Allocation and pattern write
            start_alloc = time.time()
            bytes_allocated = 0

            for i in range(num_chunks):
                if not self.running:
                    break

                try:
                    # Allocate chunk
                    chunk = bytearray(chunk_size)

                    # Write pattern (alternating 0xAA and 0x55)
                    pattern = 0xAA if i % 2 == 0 else 0x55
                    for j in range(0, len(chunk), 4096):  # Write every page
                        chunk[j] = pattern

                    allocated_chunks.append(chunk)
                    bytes_allocated += chunk_size

                except MemoryError:
                    # Can't allocate more, that's okay
                    break

            alloc_time = time.time() - start_alloc
            if alloc_time > 0 and bytes_allocated > 0:
                result.write_speed_mbps = (bytes_allocated / (1024**2)) / alloc_time

            # Phase 2: Monitoring and verification loop
            test_duration = min(duration, 30)  # Cap at 30 seconds for verification
            for elapsed in range(test_duration):
                if not self.running:
                    break

                time.sleep(1)

                # Get current memory usage
                mem = psutil.virtual_memory()
                usage_samples.append(mem.percent)

                # Verify random chunks
                chunks_to_verify = min(5, len(allocated_chunks))
                for _ in range(chunks_to_verify):
                    if not allocated_chunks:
                        break

                    idx = random.randint(0, len(allocated_chunks) - 1)
                    chunk = allocated_chunks[idx]
                    expected_pattern = 0xAA if idx % 2 == 0 else 0x55

                    # Verify pattern at random positions
                    for _ in range(10):
                        pos = random.randint(0, len(chunk) - 1)
                        pos = (pos // 4096) * 4096  # Align to page boundary
                        if pos < len(chunk) and chunk[pos] != expected_pattern:
                            errors_found += 1

                sample = {
                    'elapsed': elapsed + 1,
                    'memory_percent': mem.percent,
                    'errors': errors_found
                }
                result.samples.append(sample)

                if progress_callback:
                    progress_callback(elapsed + 1, sample)

            # Phase 3: Read speed test
            if allocated_chunks:
                start_read = time.time()
                bytes_read = 0
                for chunk in allocated_chunks[:10]:  # Read first 10 chunks
                    _ = sum(chunk[::4096])  # Read every page
                    bytes_read += len(chunk)

                read_time = time.time() - start_read
                if read_time > 0:
                    result.read_speed_mbps = (bytes_read / (1024**2)) / read_time

            # Calculate results
            result.errors_found = errors_found
            if usage_samples:
                result.max_usage_percent = max(usage_samples)
                result.avg_usage_percent = sum(usage_samples) / len(usage_samples)

            if errors_found > 0:
                result.passed = False
                result.error = f"Memory errors detected: {errors_found}"

        except Exception as e:
            result.passed = False
            result.error = str(e)

        finally:
            # Clean up - free allocated memory
            self.running = False
            allocated_chunks.clear()

        return result

    def stop(self):
        """Stop the stress test."""
        self.running = False
