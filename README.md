# VHDL-AXI4-Lite-wrapper-for-AES-GCM-module-with-CocoTB-testbench
This repository contains a AXI4-Lite wrapper for an AES-GCM module with native signals, which uses internal registers to store cryptodata. Additionally, this project also contains a testbench for CocoTB, complete with the Makefile and test runner file. 

In order to run the testbench, you only have to do a make command inside the folder where all these 4 files exist, and the test runner will run both the encryption and decryption functions described in the test, and the results as well as the prints will be shown in the same terminal.
