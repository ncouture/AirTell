#!/usr/bin/env python
"""
Passive BLE Human Radar - 2D Radio Tomographic Imaging Engine CLI Entrypoint.
Uses Sniffle BLE5 sniffers, static beacon anchors, and ambient BLE devices
for device-free human sensing and 2D spatial tomography.

Self-Documenting CLI Options:
Execute `python3 radar_tomography.py --help` for complete command line usage.
"""

from __future__ import annotations

import sys

from sniffle.radar.pipeline import (
    RadarTomographyPipeline,
    build_cli_parser,
    build_parser,
    capture_from_hardware,
    generate_simulated_samples,
    main,
    parse_radar_args,
    run_radar_pipeline,
)

__all__ = [
    "RadarTomographyPipeline",
    "build_cli_parser",
    "build_parser",
    "capture_from_hardware",
    "generate_simulated_samples",
    "main",
    "parse_radar_args",
    "run_radar_pipeline",
]

if __name__ == "__main__":
    sys.exit(main())
