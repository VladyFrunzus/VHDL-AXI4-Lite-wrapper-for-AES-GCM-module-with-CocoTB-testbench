# This file is public domain, it can be freely copied without restrictions.
# SPDX-License-Identifier: CC0-1.0

# test_runner.py

import os
import sys
from pathlib import Path
from cocotb_tools.runner import get_runner


def test_aes_gcm_runner():
    hdl_toplevel_lang = os.getenv("HDL_TOPLEVEL_LANG", "vhdl")
    sim = os.getenv("SIM", "ghdl")

    proj_path = Path(__file__).resolve().parents[2] 
    sys.path.append(str(proj_path / "model"))
    sources = [proj_path / "hdl_src" / "aes-gcm" / "aes_gcm_AXI_wrapper.vhd"]

    build_test_args = []
    if hdl_toplevel_lang == "vhdl" and sim == "xcelium":
        build_test_args = ["-v93"]

    sys.path.append(str(proj_path / "test" / "sw_ref"))

    runner = get_runner(sim)
    runner.build(
        sources=sources,
        hdl_toplevel="aes_gcm_AXI",
        always=True,
        build_args=build_test_args,
    )
    runner.test(
        hdl_toplevel="aes_gcm_AXI", test_module="test_sw_axi", test_args=build_test_args
    )

if __name__ == "__main__":
    test_aes_gcm_runner()

