# Prototype AXI4-Lite test for aes_gcm_AXI_wrapper.
# This test runs 3 test vectors from the official NIST guide.
# Both encryption and decryption is run, as 2 separate functions.

import binascii
import cocotb
from cocotb.triggers import RisingEdge, Timer

# -------------------------
# Helpers / test data
# -------------------------

def hx(s):
    return binascii.unhexlify(s.replace(" ", "").replace("\n", "").strip())

TEST_CASES = [
    # TEST CASE 13
    {
        "K": hx("00000000000000000000000000000000"
               "00000000000000000000000000000000"),
        "IV": hx("000000000000000000000000"),
        "AAD": b"",
        "P": b"",
        "EXPECTED_C": b"",
        "EXPECTED_T": hx("530f8afbc74536b9a963b4f1c4cb738b"),
        "TAG_LEN": 16,
    },
    # TEST CASE 14
    {
        "K": hx("00000000000000000000000000000000"
            "00000000000000000000000000000000"),
        "IV": hx("000000000000000000000000"),
        "AAD": b"",
        "P": hx("00000000000000000000000000000000"),
        "EXPECTED_C": hx("cea7403d4d606b6e074ec5d3baf39d18"),
        "EXPECTED_T": hx("d0d1c8a799996bf0265b98b5d48ab919"),
        "TAG_LEN": 16,
    },
    # TEST CASE 15
    {
        "K": hx("feffe9928665731c6d6a8f9467308308"
            "feffe9928665731c6d6a8f9467308308"),
        "IV": hx("cafebabefacedbaddecaf888"),
        "AAD": b"",
        "P": hx("d9313225f88406e5a55909c5aff5269a"),
        "EXPECTED_C": hx("522dc1f099567d07f47f37a32a84427d"),
        "EXPECTED_T": hx("b094dac5d93471bdec1a502270e3cc6c"),
        "TAG_LEN": 16,
    }
]

# Register offsets (must match VHDL constants)
C_AAD_BLOCKS    = 0x00000000
C_CYPH_BLOCKS   = 0x00000004
C_IV_0          = 0x00000008
C_IV_1          = 0x0000000C
C_IV_2          = 0x00000010
C_AAD_MASK_0    = 0x00000014
C_AAD_MASK_1    = 0x00000018
C_AAD_MASK_2    = 0x0000001C
C_AAD_MASK_3    = 0x00000020
C_CYPH_MASK_0   = 0x00000024
C_CYPH_MASK_1   = 0x00000028
C_CYPH_MASK_2   = 0x0000002C
C_CYPH_MASK_3   = 0x00000030
C_LEN_0         = 0x00000034
C_LEN_1         = 0x00000038
C_LEN_2         = 0x0000003C
C_LEN_3         = 0x00000040
C_KEY_0         = 0x00000044
C_KEY_1         = 0x00000048
C_KEY_2         = 0x0000004C
C_KEY_3         = 0x00000050
C_KEY_4         = 0x00000054
C_KEY_5         = 0x00000058
C_KEY_6         = 0x0000005C
C_KEY_7         = 0x00000060
C_CTRL          = 0x00000064
C_IN_DATA_0     = 0x00000068
C_IN_DATA_1     = 0x0000006C
C_IN_DATA_2     = 0x00000070
C_IN_DATA_3     = 0x00000074
C_OUT_DATA_0    = 0x00000080
C_OUT_DATA_1    = 0x00000084
C_OUT_DATA_2    = 0x00000088
C_OUT_DATA_3    = 0x0000008C
C_OUT_TAG_0     = 0x00000090
C_OUT_TAG_1     = 0x00000094
C_OUT_TAG_2     = 0x00000098
C_OUT_TAG_3     = 0x0000009C

def u32_from_be(b4: bytes) -> int:
    return int.from_bytes(b4, byteorder="big")

def split_u32_be(b: bytes):
    """Split bytes into list of 32-bit big-endian ints."""
    assert len(b) % 4 == 0
    return [u32_from_be(b[i:i+4]) for i in range(0, len(b), 4)]

async def clock_generator(dut):
    while True:
        dut.s_axi_aclk.value = 0
        await Timer(5, unit="ns")
        dut.s_axi_aclk.value = 1
        await Timer(5, unit="ns")

async def reset_dut(dut):
    # Reset polarity: g_polarity_reset='0' means s_axi_aresetn='0' asserts reset
    dut.s_axi_aresetn.value = 0
    await RisingEdge(dut.s_axi_aclk)
    await RisingEdge(dut.s_axi_aclk)
    dut.s_axi_aresetn.value = 1
    await RisingEdge(dut.s_axi_aclk)

def init_axi_signals(dut):
    dut.s_axi_awaddr.value  = 0
    dut.s_axi_awprot.value  = 0
    dut.s_axi_awvalid.value = 0

    dut.s_axi_wdata.value   = 0
    dut.s_axi_wstrb.value   = 0xF
    dut.s_axi_wvalid.value  = 0

    dut.s_axi_bready.value  = 1

    dut.s_axi_araddr.value  = 0
    dut.s_axi_arprot.value  = 0
    dut.s_axi_arvalid.value = 0

    dut.s_axi_rready.value  = 1

async def axi_write32(dut, addr: int, data: int):

    # Write data
    dut.s_axi_wdata.value   = data
    dut.s_axi_wstrb.value   = 0xF
    dut.s_axi_wvalid.value  = 1
    while True:
        await RisingEdge(dut.s_axi_aclk)
        if dut.s_axi_wready.value == 1:
            break
    dut.s_axi_wvalid.value = 0

    # Write address
    dut.s_axi_awaddr.value  = addr
    dut.s_axi_awvalid.value = 1
    while True:
        await RisingEdge(dut.s_axi_aclk)
        if dut.s_axi_awready.value == 1:
            break
    dut.s_axi_awvalid.value = 0

    # Wait for write response (B)
    while True:
        await RisingEdge(dut.s_axi_aclk)
        if dut.s_axi_bvalid.value == 1:
            # bresp is ignored here; wrapper always returns OKAY
            break

async def axi_read32(dut, addr: int) -> int:
    dut.s_axi_araddr.value  = addr
    dut.s_axi_arvalid.value = 1
    while True:
        await RisingEdge(dut.s_axi_aclk)
        if dut.s_axi_arready.value == 1:
            break
    dut.s_axi_arvalid.value = 0

    while True:
        await RisingEdge(dut.s_axi_aclk)
        if dut.s_axi_rvalid.value == 1:
            return int(dut.s_axi_rdata.value) & 0xFFFFFFFF

async def axis_ready(dut):
    while True:
        await RisingEdge(dut.s_axi_aclk)
        if dut.o_axis_ready.value == 1:
            return

# -------------------------
# Encryption Test
# -------------------------

@cocotb.test()
async def test_axi_encryption(dut):
    cocotb.start_soon(clock_generator(dut))
    init_axi_signals(dut)
    await reset_dut(dut)

    for test_idx, test_case in enumerate(TEST_CASES):
        cocotb.log.info(f"Running encryption test case {test_idx + 13}")

        K  = test_case["K"]
        IV = test_case["IV"]
        AAD = test_case["AAD"]
        P  = test_case["P"]
        EXPECTED_C = test_case["EXPECTED_C"]
        EXPECTED_T = test_case["EXPECTED_T"]

        captured_ciphertext = b""
        captured_tag = b"" 

        # Set AAD and Cypher blocks inputs
        await axi_write32(dut, C_AAD_BLOCKS, (len(AAD) + 15) // 16)
        await axi_read32(dut, C_AAD_BLOCKS)  # dummy read to test reading of other registers
        await axi_write32(dut, C_CYPH_BLOCKS, (len(P) + 15) // 16)
        await axi_read32(dut, C_CYPH_BLOCKS)  # dummy read to test reading of other registers

        # IV (96-bit) as 3x32-bit words, big-endian mapping into iv(95:0)
        iv_words = split_u32_be(IV)  # 3 words
        await axi_write32(dut, C_IV_0, iv_words[0])
        await axi_write32(dut, C_IV_1, iv_words[1])
        await axi_write32(dut, C_IV_2, iv_words[2])

        # Initialize masks to all 1s (no masking)
        for mask in (C_AAD_MASK_0, C_AAD_MASK_1, C_AAD_MASK_2, C_AAD_MASK_3):
            await axi_write32(dut, mask, 0xFFFFFFFF)
        for mask in (C_CYPH_MASK_0, C_CYPH_MASK_1, C_CYPH_MASK_2, C_CYPH_MASK_3):
            await axi_write32(dut, mask, 0xFFFFFFFF)

        # Length (128-bit): [len(AAD)*8 || len(P)*8]
        aad_bits = len(AAD) * 8
        p_bits   = len(P) * 8
        length128 = ((aad_bits & ((1<<64)-1)) << 64) | (p_bits & ((1<<64)-1))
        len_words = [(length128 >> 96) & 0xFFFFFFFF,
                    (length128 >> 64) & 0xFFFFFFFF,
                    (length128 >> 32) & 0xFFFFFFFF,
                    (length128 >>  0) & 0xFFFFFFFF]
        await axi_write32(dut, C_LEN_0, len_words[0])
        await axi_write32(dut, C_LEN_1, len_words[1])
        await axi_write32(dut, C_LEN_2, len_words[2])
        await axi_write32(dut, C_LEN_3, len_words[3])

        # Key (256-bit): 8x32-bit big-endian words mapping into key(255:0)
        key_words = split_u32_be(K)  # 8 words
        await axi_write32(dut, C_KEY_0, key_words[0])
        await axi_write32(dut, C_KEY_1, key_words[1])
        await axi_write32(dut, C_KEY_2, key_words[2])
        await axi_write32(dut, C_KEY_3, key_words[3])
        await axi_write32(dut, C_KEY_4, key_words[4])
        await axi_write32(dut, C_KEY_5, key_words[5])
        await axi_write32(dut, C_KEY_6, key_words[6])
        await axi_write32(dut, C_KEY_7, key_words[7])

        # CTRL: bit 1 = 1 (start/gcm_en), bit 0 = 1 (encrypt)
        await axi_write32(dut, C_CTRL, 0b11)

        aad_blocks_data = [AAD[i:i+16] for i in range(0, len(AAD), 16)]
        for block in aad_blocks_data:
            # --- Set AAD mask for this block ---
            aad_mask = ((1<<len(block.hex())*4)-1)<<((128-len(block.hex())*4))
            aad_mask_data = split_u32_be(aad_mask.to_bytes(16, "big"))
            if aad_mask_data[0] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_0, aad_mask_data[0])
            if aad_mask_data[1] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_1, aad_mask_data[1])
            if aad_mask_data[2] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_2, aad_mask_data[2])
            if aad_mask_data[3] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_3, aad_mask_data[3])

            # --- Send 128-bit AAD block via C_IN_DATA_0..3 ---
            aad_words = split_u32_be(block.ljust(16, b'\x00'))  # pad to 16 bytes
            await axi_write32(dut, C_IN_DATA_0, aad_words[0])
            await axi_write32(dut, C_IN_DATA_1, aad_words[1])
            await axi_write32(dut, C_IN_DATA_2, aad_words[2])
            await axi_write32(dut, C_IN_DATA_3, aad_words[3])

            # --- Wait until AES Core AXIS is ready ---
            await axis_ready(dut)

        p_blocks_data = [P[i:i+16] for i in range(0, len(P), 16)]
        for idx, block in enumerate(p_blocks_data):
            # --- Set CYPH mask for this block ---
            cyph_mask = ((1<<len(block.hex())*4)-1)<<((128-len(block.hex())*4))
            cyph_mask_data = split_u32_be(cyph_mask.to_bytes(16, "big"))
            if cyph_mask_data[0] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_0, cyph_mask_data[0])
            if cyph_mask_data[1] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_1, cyph_mask_data[1])
            if cyph_mask_data[2] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_2, cyph_mask_data[2])
            if cyph_mask_data[3] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_3, cyph_mask_data[3])
            
            # --- Send 128-bit PT block via C_IN_DATA_0..3 ---
            pt_words = split_u32_be(block.ljust(16, b'\x00'))  # pad to 16 bytes
            await axi_write32(dut, C_IN_DATA_0, pt_words[0])
            await axi_write32(dut, C_IN_DATA_1, pt_words[1])
            await axi_write32(dut, C_IN_DATA_2, pt_words[2])
            await axi_write32(dut, C_IN_DATA_3, pt_words[3])

            # --- Wait until AES Core AXIS is ready ---
            await axis_ready(dut)

            # --- Wait for done flag ---
            got_text_done = False
            timeout = 20000  # cycles

            for _ in range(timeout):
                await RisingEdge(dut.s_axi_aclk)
                if dut.o_text_done.value == 1:
                    got_text_done = True
                    break

            assert got_text_done, "Timed out waiting for o_text_done"

            # --- Read outputs (128-bit data + 128-bit tag) ---
            out_data_words = b""
            await axi_read32(dut, C_OUT_DATA_0)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
            await axi_read32(dut, C_OUT_DATA_1)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
            await axi_read32(dut, C_OUT_DATA_2)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
            await axi_read32(dut, C_OUT_DATA_3)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")

            valid_bytes = (cyph_mask.bit_count()+7)//8
            captured_ciphertext += out_data_words[:valid_bytes]

        # Clear start bit
        await axi_write32(dut, C_CTRL, 0b01)

        timeout = 20000  # cycles
        got_tag_done = False

        for _ in range(timeout):
            await RisingEdge(dut.s_axi_aclk)
            if dut.o_tag_done.value == 1:
                got_tag_done = True
                break

        assert got_tag_done, "Timed out waiting for o_tag_done"
        
        # --- Read outputs (128-bit data + 128-bit tag) ---
        await axi_read32(dut, C_OUT_TAG_0)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
        await axi_read32(dut, C_OUT_TAG_1)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
        await axi_read32(dut, C_OUT_TAG_2)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
        await axi_read32(dut, C_OUT_TAG_3)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")

        # --- Verify ciphertext ---
        if len(captured_ciphertext) > 0:       
            assert captured_ciphertext == EXPECTED_C, f"Test case {test_idx+13}: Hardware ciphertext mismatch\nExpected: {EXPECTED_C.hex()}\nGot: {captured_ciphertext.hex()}"
            cocotb.log.info(f"Test case {test_idx+13}: Ciphertext verified ✓")
        else:
            # Verify ciphertext
            assert len(P) == 0, f"Test case {test_idx+13}: Expected empty ciphertext, but it was not empty"
            cocotb.log.info(f"Test case {test_idx+13}: Empty plaintext - no output blocks expected ✓")

        if len(captured_tag) > 0:
            assert captured_tag == EXPECTED_T, f"Test case {test_idx+13}: Hardware tag mismatch\nExpected: {EXPECTED_T.hex()}\nGot: {captured_tag.hex()}"
            cocotb.log.info(f"Test case {test_idx+13}: Tag verified ✓")
        else:
            cocotb.log.error(f"Test case {test_idx+13}: Tag was empty")

# -------------------------
# Decryption Test
# -------------------------

@cocotb.test()
async def test_axi_decryption(dut):
    cocotb.start_soon(clock_generator(dut))
    init_axi_signals(dut)
    await reset_dut(dut)

    for test_idx, test_case in enumerate(TEST_CASES):
        cocotb.log.info(f"Running decryption test case {test_idx + 13}")

        K  = test_case["K"]
        IV = test_case["IV"]
        AAD = test_case["AAD"]
        C = test_case["EXPECTED_C"]
        EXPECTED_P = test_case["P"]
        EXPECTED_T = test_case["EXPECTED_T"]

        captured_plaintext = b""
        captured_tag = b"" 

        # Set AAD and Cypher blocks inputs
        await axi_write32(dut, C_AAD_BLOCKS, (len(AAD) + 15) // 16)
        await axi_write32(dut, C_CYPH_BLOCKS, (len(C) + 15) // 16)

        # IV (96-bit) as 3x32-bit words, big-endian mapping into iv(95:0)
        iv_words = split_u32_be(IV)  # 3 words
        await axi_write32(dut, C_IV_0, iv_words[0])
        await axi_write32(dut, C_IV_1, iv_words[1])
        await axi_write32(dut, C_IV_2, iv_words[2])

        # Initialize masks to all 1s (no masking)
        for mask in (C_AAD_MASK_0, C_AAD_MASK_1, C_AAD_MASK_2, C_AAD_MASK_3):
            await axi_write32(dut, mask, 0xFFFFFFFF)
        for mask in (C_CYPH_MASK_0, C_CYPH_MASK_1, C_CYPH_MASK_2, C_CYPH_MASK_3):
            await axi_write32(dut, mask, 0xFFFFFFFF)

        # Length (128-bit): [len(AAD)*8 || len(P)*8]
        aad_bits = len(AAD) * 8
        c_bits   = len(C) * 8
        length128 = ((aad_bits & ((1<<64)-1)) << 64) | (c_bits & ((1<<64)-1))
        len_words = [(length128 >> 96) & 0xFFFFFFFF,
                    (length128 >> 64) & 0xFFFFFFFF,
                    (length128 >> 32) & 0xFFFFFFFF,
                    (length128 >>  0) & 0xFFFFFFFF]
        await axi_write32(dut, C_LEN_0, len_words[0])
        await axi_write32(dut, C_LEN_1, len_words[1])
        await axi_write32(dut, C_LEN_2, len_words[2])
        await axi_write32(dut, C_LEN_3, len_words[3])

        # Key (256-bit): 8x32-bit big-endian words mapping into key(255:0)
        key_words = split_u32_be(K)  # 8 words
        await axi_write32(dut, C_KEY_0, key_words[0])
        await axi_write32(dut, C_KEY_1, key_words[1])
        await axi_write32(dut, C_KEY_2, key_words[2])
        await axi_write32(dut, C_KEY_3, key_words[3])
        await axi_write32(dut, C_KEY_4, key_words[4])
        await axi_write32(dut, C_KEY_5, key_words[5])
        await axi_write32(dut, C_KEY_6, key_words[6])
        await axi_write32(dut, C_KEY_7, key_words[7])

        # CTRL: bit 1 = 1 (start/gcm_en), bit 0 = 0 (decrypt)
        await axi_write32(dut, C_CTRL, 0b10)

        aad_blocks_data = [AAD[i:i+16] for i in range(0, len(AAD), 16)]
        for block in aad_blocks_data:
            # --- Set AAD mask for this block ---
            aad_mask = ((1<<len(block.hex())*4)-1)<<((128-len(block.hex())*4))
            aad_mask_data = split_u32_be(aad_mask.to_bytes(16, "big"))
            if aad_mask_data[0] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_0, aad_mask_data[0])
            if aad_mask_data[1] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_1, aad_mask_data[1])
            if aad_mask_data[2] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_2, aad_mask_data[2])
            if aad_mask_data[3] != 0xFFFFFFFF:
                await axi_write32(dut, C_AAD_MASK_3, aad_mask_data[3])

            # --- Send 128-bit AAD block via C_IN_DATA_0..3 ---
            aad_words = split_u32_be(block.ljust(16, b'\x00'))  # pad to 16 bytes
            await axi_write32(dut, C_IN_DATA_0, aad_words[0])
            await axi_write32(dut, C_IN_DATA_1, aad_words[1])
            await axi_write32(dut, C_IN_DATA_2, aad_words[2])
            await axi_write32(dut, C_IN_DATA_3, aad_words[3])

            # --- Wait until AES Core AXIS is ready ---
            await axis_ready(dut)

        c_blocks_data = [C[i:i+16] for i in range(0, len(C), 16)]
        for idx, block in enumerate(c_blocks_data):
            # --- Set CYPH mask for this block ---
            cyph_mask = ((1<<len(block.hex())*4)-1)<<((128-len(block.hex())*4))
            cyph_mask_data = split_u32_be(cyph_mask.to_bytes(16, "big"))
            if cyph_mask_data[0] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_0, cyph_mask_data[0])
            if cyph_mask_data[1] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_1, cyph_mask_data[1])
            if cyph_mask_data[2] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_2, cyph_mask_data[2])
            if cyph_mask_data[3] != 0xFFFFFFFF:
                await axi_write32(dut, C_CYPH_MASK_3, cyph_mask_data[3])
            
            # --- Send 128-bit PT block via C_IN_DATA_0..3 ---
            ct_words = split_u32_be(block.ljust(16, b'\x00'))  # pad to 16 bytes
            await axi_write32(dut, C_IN_DATA_0, ct_words[0])
            await axi_write32(dut, C_IN_DATA_1, ct_words[1])
            await axi_write32(dut, C_IN_DATA_2, ct_words[2])
            await axi_write32(dut, C_IN_DATA_3, ct_words[3])

            # --- Wait until AES Core AXIS is ready ---
            await axis_ready(dut)

            # --- Wait for done flag ---
            got_text_done = False
            timeout = 20000  # cycles

            for _ in range(timeout):
                await RisingEdge(dut.s_axi_aclk)
                if dut.o_text_done.value == 1:
                    got_text_done = True
                    break

            assert got_text_done, "Timed out waiting for o_text_done"

            # --- Read outputs (128-bit data + 128-bit tag) ---
            out_data_words = b""
            await axi_read32(dut, C_OUT_DATA_0)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
            await axi_read32(dut, C_OUT_DATA_1)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
            await axi_read32(dut, C_OUT_DATA_2)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
            await axi_read32(dut, C_OUT_DATA_3)
            out_data_words += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")

            valid_bytes = (cyph_mask.bit_count()+7)//8
            captured_plaintext += out_data_words[:valid_bytes]

        # Clear start bit
        await axi_write32(dut, C_CTRL, 0b00)

        timeout = 20000  # cycles
        got_tag_done = False

        for _ in range(timeout):
            await RisingEdge(dut.s_axi_aclk)
            if dut.o_tag_done.value == 1:
                got_tag_done = True
                break

        assert got_tag_done, "Timed out waiting for o_tag_done"
        
        # --- Read outputs (128-bit data + 128-bit tag) ---
        await axi_read32(dut, C_OUT_TAG_0)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
        await axi_read32(dut, C_OUT_TAG_1)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
        await axi_read32(dut, C_OUT_TAG_2)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")
        await axi_read32(dut, C_OUT_TAG_3)
        captured_tag += dut.s_axi_rdata.value.to_unsigned().to_bytes(4, "big")

        # --- Verify plaintext ---
        if len(captured_plaintext) > 0:       
            assert captured_plaintext == EXPECTED_P, f"Test case {test_idx+13}: Hardware plaintext mismatch\nExpected: {EXPECTED_P.hex()}\nGot: {captured_plaintext.hex()}"
            cocotb.log.info(f"Test case {test_idx+13}: Plaintext verified ✓")
        else:
            # Verify ciphertext
            assert len(C) == 0, f"Test case {test_idx+13}: Expected empty plaintext, but it was not empty"
            cocotb.log.info(f"Test case {test_idx+13}: Empty ciphertext - no output blocks expected ✓")

        if len(captured_tag) > 0:
            assert captured_tag == EXPECTED_T, f"Test case {test_idx+13}: Hardware tag mismatch\nExpected: {EXPECTED_T.hex()}\nGot: {captured_tag.hex()}"
            cocotb.log.info(f"Test case {test_idx+13}: Tag verified ✓")
        else:
            cocotb.log.error(f"Test case {test_idx+13}: Tag was empty")