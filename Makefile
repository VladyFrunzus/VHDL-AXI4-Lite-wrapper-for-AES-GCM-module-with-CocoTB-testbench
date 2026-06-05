# Copyright cocotb contributors
# Copyright (c) 2013 Potential Ventures Ltd
# Copyright (c) 2013 SolarFlare Communications Inc
# Licensed under the Revised BSD License, see LICENSE for details.
# SPDX-License-Identifier: BSD-3-Clause

SIM ?= ghdl
TOPLEVEL_LANG ?= vhdl

PWD=$(shell pwd)

export PYTHONPATH := $(PWD)/../../model:$(PYTHONPATH)

VHDL_SOURCES = $(shell find $(PWD)/../../hdl_src/aes-gcm -name "*.vhd")

ifeq ($(SIM),ghdl)
    SIM_ARGS += --wave=sim_build/wave.ghw
    GHDL_ARGS = --work=work
endif

ifneq ($(filter $(SIM),ius xcelium),)
    COMPILE_ARGS += -v93
endif

COCOTB_TOPLEVEL     := aes_gcm_axi
COCOTB_TEST_MODULES := test_sw_axi

include $(shell cocotb-config --makefiles)/Makefile.sim
