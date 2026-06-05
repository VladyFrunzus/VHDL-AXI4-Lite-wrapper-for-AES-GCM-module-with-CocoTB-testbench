-- This is an AXI wrapper for a specific AES-GCM core implemented in VHDL.
-- Its purpose is to serve as a universal interface (AXI4-Lite) for easier integration
-- of the original module in other projects, module which uses discrete ports. 

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity aes_gcm_axi is
  generic (
    g_polarity_reset : std_logic := '0'
  );
  port (
    
    -- Global signals
    s_axi_aclk   : in  std_logic;
    s_axi_aresetn   : in  std_logic;

    -- Operation done flags
    o_text_done : out std_logic; -- Indicates that the AES core has produced a valid cyphertext output
    o_tag_done  : out std_logic; -- Indicates that the AES core has produced a valid authentication tag
    o_axis_ready : out std_logic; -- Indicates that the AES core has signalled ready on the AXI-Stream interface

    -- AXI4-Lite Slave Interface Signals
    -- Write address channel (AW)
    s_axi_awaddr  : in  std_logic_vector(32-1 downto 0);
    s_axi_awprot  : in  std_logic_vector(2 downto 0);
    s_axi_awvalid : in  std_logic;
    s_axi_awready : out std_logic;

    -- Write data channel (W)
    s_axi_wdata   : in  std_logic_vector(32-1 downto 0); -- typically 31 downto 0
    s_axi_wstrb   : in  std_logic_vector((32/8)-1 downto 0); -- typically 3 downto 0
    s_axi_wvalid  : in  std_logic;
    s_axi_wready  : out std_logic;

    -- Write response channel (B)
    s_axi_bresp   : out std_logic_vector(1 downto 0);
    s_axi_bvalid  : out std_logic;
    s_axi_bready  : in  std_logic;

    -- Read address channel (AR)
    s_axi_araddr  : in  std_logic_vector(32-1 downto 0);
    s_axi_arprot  : in  std_logic_vector(2 downto 0);
    s_axi_arvalid : in  std_logic;
    s_axi_arready : out std_logic;

    -- Read data channel (R)
    s_axi_rdata   : out std_logic_vector(32-1 downto 0); -- typically 31 downto 0
    s_axi_rresp   : out std_logic_vector(1 downto 0);
    s_axi_rvalid  : out std_logic;
    s_axi_rready  : in  std_logic
  );
end entity;

architecture rtl of aes_gcm_axi is

-- ====================================================
-- REGISTER MAP (BYTE OFFSETS)
-- ====================================================

constant C_AAD_BLOCKS    : std_logic_vector(31 downto 0) := x"00000000"; -- W
constant C_CYPH_BLOCKS   : std_logic_vector(31 downto 0) := x"00000004"; -- W

constant C_IV_0          : std_logic_vector(31 downto 0) := x"00000008"; -- W
constant C_IV_1          : std_logic_vector(31 downto 0) := x"0000000C"; -- W
constant C_IV_2          : std_logic_vector(31 downto 0) := x"00000010"; -- W

constant C_AAD_MASK_0    : std_logic_vector(31 downto 0) := x"00000014"; -- W
constant C_AAD_MASK_1    : std_logic_vector(31 downto 0) := x"00000018"; -- W
constant C_AAD_MASK_2    : std_logic_vector(31 downto 0) := x"0000001C"; -- W
constant C_AAD_MASK_3    : std_logic_vector(31 downto 0) := x"00000020"; -- W

constant C_CYPH_MASK_0   : std_logic_vector(31 downto 0) := x"00000024"; -- W
constant C_CYPH_MASK_1   : std_logic_vector(31 downto 0) := x"00000028"; -- W
constant C_CYPH_MASK_2   : std_logic_vector(31 downto 0) := x"0000002C"; -- W
constant C_CYPH_MASK_3   : std_logic_vector(31 downto 0) := x"00000030"; -- W

constant C_LEN_0         : std_logic_vector(31 downto 0) := x"00000034"; -- W
constant C_LEN_1         : std_logic_vector(31 downto 0) := x"00000038"; -- W
constant C_LEN_2         : std_logic_vector(31 downto 0) := x"0000003C"; -- W
constant C_LEN_3         : std_logic_vector(31 downto 0) := x"00000040"; -- W

constant C_KEY_0         : std_logic_vector(31 downto 0) := x"00000044"; -- W
constant C_KEY_1         : std_logic_vector(31 downto 0) := x"00000048"; -- W
constant C_KEY_2         : std_logic_vector(31 downto 0) := x"0000004C"; -- W
constant C_KEY_3         : std_logic_vector(31 downto 0) := x"00000050"; -- W
constant C_KEY_4         : std_logic_vector(31 downto 0) := x"00000054"; -- W
constant C_KEY_5         : std_logic_vector(31 downto 0) := x"00000058"; -- W
constant C_KEY_6         : std_logic_vector(31 downto 0) := x"0000005C"; -- W
constant C_KEY_7         : std_logic_vector(31 downto 0) := x"00000060"; -- W

constant C_CTRL          : std_logic_vector(31 downto 0) := x"00000064"; -- W
-- NOTE: SET THIS LAST, AS THIS STARTS THE OPERATION
-- bit0 = encryption_mode (0 = decrypt, 1 = encrypt)
-- bit1 = gcm_en (start operation)

constant C_IN_DATA_0          : std_logic_vector(31 downto 0) := x"00000068"; -- W
constant C_IN_DATA_1          : std_logic_vector(31 downto 0) := x"0000006C"; -- W
constant C_IN_DATA_2          : std_logic_vector(31 downto 0) := x"00000070"; -- W
constant C_IN_DATA_3          : std_logic_vector(31 downto 0) := x"00000074"; -- W

-- constant C_STATUS        : std_logic_vector(31 downto 0) := x"00000078"; -- R
-- -- bit0 = out_data_valid_latched
-- -- bit1 = s_ready (live)
-- -- bit2 = tag_valid_latched

constant C_OUT_DATA_0         : std_logic_vector(31 downto 0) := x"00000080"; -- R
constant C_OUT_DATA_1         : std_logic_vector(31 downto 0) := x"00000084"; -- R
constant C_OUT_DATA_2         : std_logic_vector(31 downto 0) := x"00000088"; -- R
constant C_OUT_DATA_3         : std_logic_vector(31 downto 0) := x"0000008C"; -- R

constant C_OUT_TAG_0         : std_logic_vector(31 downto 0) := x"00000090"; -- R
constant C_OUT_TAG_1         : std_logic_vector(31 downto 0) := x"00000094"; -- R
constant C_OUT_TAG_2         : std_logic_vector(31 downto 0) := x"00000098"; -- R
constant C_OUT_TAG_3         : std_logic_vector(31 downto 0) := x"0000009C"; -- R

constant C_ZERO32 : std_logic_vector(31 downto 0) := (others => '0');
-- Used for comparison in if statement

-- ====================================================
-- OUT PORT SIGNAL COPIES
-- ====================================================

signal awready : std_logic;
signal wready  : std_logic;
signal bvalid  : std_logic;
signal arready : std_logic;
signal rvalid  : std_logic;
signal rdata   : std_logic_vector(31 downto 0);
signal bresp   : std_logic_vector(1 downto 0);
signal rresp   : std_logic_vector(1 downto 0);
signal text_done : std_logic := '0';
signal tag_done  : std_logic := '0';
signal axis_ready : std_logic := '0';

-- ====================================================
-- AES_GCM MODULE SIGNALS
-- ====================================================

signal s_aad_blocks, s_cypher_blocks : std_logic_vector ( 32 - 1 downto 0 );
signal s_iv : std_logic_vector ( 96 - 1 downto 0 );
signal s_aad_mask, s_cypher_mask : std_logic_vector ( 128 - 1 downto 0 );
signal s_length : std_logic_vector ( 128 - 1 downto 0 );
signal s_key : std_logic_vector ( 256 - 1 downto 0 );
signal s_encryption_mode : std_logic;
signal s_gcm_en : std_logic;

signal s_s_valid : std_logic;
signal s_s_ready : std_logic;
signal s_s_data : std_logic_vector ( 128 - 1 downto 0 );

signal s_data : std_logic_vector ( 128 - 1 downto 0 );
signal s_valid : std_logic;

signal s_tag : std_logic_vector ( 128 - 1 downto 0 );
signal s_tag_en : std_logic;

-- ====================================================
-- INTERNAL LATCHING DATA SIGNALS
-- ====================================================

signal r_s_data : std_logic_vector ( 128 - 1 downto 0 );

signal r_out_data : std_logic_vector ( 128 - 1 downto 0 );
signal r_out_tag : std_logic_vector ( 128 - 1 downto 0 );

signal r_latched_addr : std_logic_vector ( 32 - 1 downto 0 );
signal r_addr_loaded : std_logic;
signal r_latched_data : std_logic_vector ( 32 - 1 downto 0 );
signal r_data_loaded : std_logic;
signal r_read_loaded : std_logic;
signal r_expected_num : std_logic_vector ( 32 - 1 downto 0 ) := (others => '0');
signal r_data_done : std_logic;

-- ====================================================
begin
  s_axi_awready <= awready;
  s_axi_wready  <= wready;
  s_axi_bvalid  <= bvalid;
  s_axi_bresp   <= bresp;

  s_axi_arready <= arready;
  s_axi_rvalid  <= rvalid;
  s_axi_rdata   <= rdata;
  s_axi_rresp   <= rresp;

  o_text_done <= text_done;
  o_tag_done <= tag_done;
  o_axis_ready <= axis_ready;

  -- Instantiate AES-GCM
  u_aes : entity work.aes_gcm(rtl)
    generic map (
      g_polarity_reset => g_polarity_reset
    )
    port map (
      i_clk            => s_axi_aclk,
      i_rst            => s_axi_aresetn,

      i_aad_blocks     => s_aad_blocks,
      i_cypher_blocks  => s_cypher_blocks,
      i_iv             => s_iv,
      i_aad_mask       => s_aad_mask,
      i_cypher_mask    => s_cypher_mask,
      i_length         => s_length,
      i_encryption_key => s_key,
      i_encryption_mode=> s_encryption_mode,
      i_gcm_en         => s_gcm_en,

      i_s_valid        => s_s_valid,
      o_s_ready        => s_s_ready,
      i_s_data         => s_s_data,

      o_data           => s_data,
      o_valid          => s_valid, 

      o_tag            => s_tag,
      o_tag_en         => s_tag_en
    );

  -- Read/Write process
  Process(s_axi_aclk, s_axi_aresetn)
  begin

    if s_axi_aclk'event and s_axi_aclk = '1' then

      if s_axi_aresetn = g_polarity_reset then

        s_aad_blocks <= (others => '0');
        s_cypher_blocks <= (others => '0');
        s_iv <= (others => '0');
        s_aad_mask <= (others => '0');
        s_cypher_mask <= (others => '0');
        s_length <= (others => '0');
        s_key <= (others => '0');
        s_encryption_mode <= '0';
        s_gcm_en <= '0';

        awready <= '0';
        wready <= '0';
        bvalid <= '0';
        bresp <= (others => '0');
        arready <= '0';
        rvalid <= '0';
        rresp <= (others => '0');
        rdata <= (others => '0');

      else

        -- Write address channel
        if s_axi_awvalid = '1' and awready = '0' then
          awready <= '1';
        else
          awready <= '0';
        end if;

        if s_axi_awvalid = '1' and awready = '1' then
          r_latched_addr <= s_axi_awaddr;
          r_addr_loaded <= '1';
          awready <= '0';
        end if;

        -- Write data channel
        if s_axi_wvalid = '1' and wready = '0' then
          wready <= '1';
        else
          wready <= '0';
        end if;

        if s_axi_wvalid = '1' and wready = '1' then
          r_latched_data <= s_axi_wdata;
          r_data_loaded <= '1';
          wready <= '0';
        end if;

        if r_addr_loaded = '1' and r_data_loaded = '1' then
          case r_latched_addr is
            when C_AAD_BLOCKS =>
              s_aad_blocks <= r_latched_data; --and s_axi_wstrb;
              -- r_expected_num is set in another process in order to avoid multiple drivers error
            when C_CYPH_BLOCKS =>
              s_cypher_blocks <= r_latched_data; --and s_axi_wstrb;
              -- r_expected_num is set in another process in order to avoid multiple drivers error
            when C_IV_0 =>
              s_iv(95 downto 64) <= r_latched_data; --and s_axi_wstrb;
            when C_IV_1 =>
              s_iv(63 downto 32) <= r_latched_data; --and s_axi_wstrb;
            when C_IV_2 =>
              s_iv(31 downto  0) <= r_latched_data; --and s_axi_wstrb;
            when C_AAD_MASK_0 =>
              s_aad_mask(127 downto 96) <= r_latched_data; --and s_axi_wstrb;
            when C_AAD_MASK_1 =>
              s_aad_mask(95 downto 64) <= r_latched_data; --and s_axi_wstrb;
            when C_AAD_MASK_2 =>
              s_aad_mask(63 downto 32) <= r_latched_data; --and s_axi_wstrb;
            when C_AAD_MASK_3 =>
              s_aad_mask(31 downto 0) <= r_latched_data; --and s_axi_wstrb;
            when C_CYPH_MASK_0 =>
              s_cypher_mask(127 downto 96) <= r_latched_data; --and s_axi_wstrb;
            when C_CYPH_MASK_1 =>
              s_cypher_mask(95 downto 64) <= r_latched_data; --and s_axi_wstrb;
            when C_CYPH_MASK_2 =>
              s_cypher_mask(63 downto 32) <= r_latched_data; --and s_axi_wstrb;
            when C_CYPH_MASK_3 =>
              s_cypher_mask(31 downto 0) <= r_latched_data; --and s_axi_wstrb;
            when C_LEN_0 =>
              s_length(127 downto 96) <= r_latched_data; --and s_axi_wstrb;
            when C_LEN_1 =>
              s_length(95 downto 64) <= r_latched_data; --and s_axi_wstrb;
            when C_LEN_2 =>
              s_length(63 downto 32) <= r_latched_data; --and s_axi_wstrb;
            when C_LEN_3 =>
              s_length(31 downto 0) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_0 =>
              s_key(255 downto 224) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_1 =>
              s_key(223 downto 192) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_2 =>
              s_key(191 downto 160) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_3 =>
              s_key(159 downto 128) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_4 =>
              s_key(127 downto 96) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_5 =>
              s_key(95 downto 64) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_6 =>
              s_key(63 downto 32) <= r_latched_data; --and s_axi_wstrb;
            when C_KEY_7 =>
              s_key(31 downto 0) <= r_latched_data; --and s_axi_wstrb;
            when C_CTRL =>
              s_encryption_mode <= r_latched_data(0); --and s_axi_wstrb(0);
              s_gcm_en <= r_latched_data(1); --and s_axi_wstrb(0);
            when C_IN_DATA_0 =>
              r_s_data(127 downto 96) <= r_latched_data; --and s_axi_wstrb;
            when C_IN_DATA_1 =>
              r_s_data(95 downto 64) <= r_latched_data; --and s_axi_wstrb;
            when C_IN_DATA_2 =>
              r_s_data(63 downto 32) <= r_latched_data; --and s_axi_wstrb;
            when C_IN_DATA_3 =>
              r_s_data(31 downto 0) <= r_latched_data; --and s_axi_wstrb;
              r_data_done <= '1';
            when others =>
              report "AES-GCM AXI Wrapper: Write to invalid address " & integer'image(to_integer(unsigned(r_latched_addr)));
          end case;

          r_addr_loaded <= '0';
          r_data_loaded <= '0';
        end if;

        if r_data_done = '1' then
          r_data_done <= '0';
        end if;

        -- Write response channel
        -- NOTE: Write response is always generated as "OKAY"
        if s_axi_bready = '1' and s_axi_wvalid = '0' and bvalid = '0' then
          bvalid <= '1';
          bresp <= "00"; -- OKAY
        end if;

        if bvalid = '1' then
          bvalid <= '0';
        end if;

        -- Read address channel
        if s_axi_arvalid = '1' and arready = '0' then
          arready <= '1';
        else
          arready <= '0';
        end if;

        if s_axi_arvalid = '1' and arready = '1' then
          r_latched_addr <= s_axi_araddr;
          r_read_loaded <= '1';
          arready <= '0';
        end if;

        -- Read data channel
        if s_axi_rready = '1' and rvalid = '0' and r_read_loaded = '1' then
          case r_latched_addr is
            when C_AAD_BLOCKS =>
              rdata <= s_aad_blocks;
            when C_CYPH_BLOCKS =>
              rdata <= s_cypher_blocks;
            when C_IV_0 =>
              rdata <= s_iv(95 downto 64);
            when C_IV_1 =>
              rdata <= s_iv(63 downto 32);
            when C_IV_2 =>
              rdata <= s_iv(31 downto  0);
            when C_AAD_MASK_0 =>
              rdata <= s_aad_mask(127 downto 96);
            when C_AAD_MASK_1 =>
              rdata <= s_aad_mask(95 downto 64);
            when C_AAD_MASK_2 =>
              rdata <= s_aad_mask(63 downto 32);
            when C_AAD_MASK_3 =>
              rdata <= s_aad_mask(31 downto 0);
            when C_CYPH_MASK_0 =>
              rdata <= s_cypher_mask(127 downto 96);
            when C_CYPH_MASK_1 =>
              rdata <= s_cypher_mask(95 downto 64);
            when C_CYPH_MASK_2 =>
              rdata <= s_cypher_mask(63 downto 32);
            when C_CYPH_MASK_3 =>
              rdata <= s_cypher_mask(31 downto 0);
            when C_LEN_0 =>
              rdata <= s_length(127 downto 96);
            when C_LEN_1 =>
              rdata <= s_length(95 downto 64);
            when C_LEN_2 =>
              rdata <= s_length(63 downto 32);
            when C_LEN_3 =>
              rdata <= s_length(31 downto 0);
            when C_KEY_0 =>
              rdata <= s_key(255 downto 224);
            when C_KEY_1 =>
              rdata <= s_key(223 downto 192);
            when C_KEY_2 =>
              rdata <= s_key(191 downto 160);
            when C_KEY_3 =>
              rdata <= s_key(159 downto 128);
            when C_KEY_4 =>
              rdata <= s_key(127 downto 96);
            when C_KEY_5 =>
              rdata <= s_key(95 downto 64);
            when C_KEY_6 =>
              rdata <= s_key(63 downto 32);
            when C_KEY_7 =>
              rdata <= s_key(31 downto 0);
            when C_CTRL =>
              rdata <= (31 downto 2 => '0') & s_gcm_en & s_encryption_mode; -- bit0 = encryption_mode (0 = decrypt, 1 = encrypt), bit1 = gcm_en
            when C_IN_DATA_0 =>
              rdata <= r_s_data(127 downto 96);
            when C_IN_DATA_1 =>
              rdata <= r_s_data(95 downto 64);
            when C_IN_DATA_2 =>
              rdata <= r_s_data(63 downto 32);
            when C_IN_DATA_3 =>
              rdata <= r_s_data(31 downto 0);
            when C_OUT_DATA_0 =>
              rdata <= r_out_data(127 downto 96);
            when C_OUT_DATA_1 =>
              rdata <= r_out_data(95 downto 64);
            when C_OUT_DATA_2 =>
              rdata <= r_out_data(63 downto 32);
            when C_OUT_DATA_3 =>
              rdata <= r_out_data(31 downto 0);
            when C_OUT_TAG_0 =>
              rdata <= r_out_tag(127 downto 96);
            when C_OUT_TAG_1 =>
              rdata <= r_out_tag(95 downto 64);
            when C_OUT_TAG_2 =>
              rdata <= r_out_tag(63 downto 32);
            when C_OUT_TAG_3 =>
              rdata <= r_out_tag(31 downto 0);
            when others =>
              rdata <= (others => '0');
          end case;

          -- NOTE: Read response is always "OKAY"
          rresp <= "00"; -- OKAY
          rvalid <= '1';
          r_read_loaded <= '0';
        end if;

        if rvalid = '1' then
          rvalid <= '0';
        end if;

      end if;

    end if;

  End Process;

  -- Transmit data to the AES-GCM core
  Process(s_axi_aclk, s_axi_aresetn)
  begin

    if s_axi_aclk'event and s_axi_aclk = '1' then

      if s_axi_aresetn = g_polarity_reset then
        
        s_s_valid <= '0';
        s_s_data <= (others => '0');

        r_expected_num <= (others => '0');

      else
        
        -- We set r_expected_num in this process in order to avoid multiple drivers error
        if s_axi_wvalid = '1' and wready = '1' and (r_latched_addr = C_CYPH_BLOCKS or r_latched_addr = C_AAD_BLOCKS) then
          r_expected_num <= std_logic_vector(unsigned(r_expected_num) + unsigned(s_axi_wdata));
        end if;

        if r_expected_num /= C_ZERO32 and r_data_done = '1' then
          s_s_valid <= '1';
          s_s_data <= r_s_data;
        end if;

        if s_s_valid = '1' then
          if s_s_ready = '1' then
            r_expected_num <= std_logic_vector(unsigned(r_expected_num) - 1);
            s_s_valid <= '0';

            -- NOTE: Slight issue with the situation where the test doesn't stop sending PT/CT after a multiple of 128 bits,
            -- since the AES_GCM core won't be ready to accept new data until the previous block is processed.
            -- Not even hanging the transfer would help, since there is still the issue with storing the results of the previous block.
          end if;
        end if;
      end if;
    end if;
  
  End Process;

  -- Receive data from the AES-GCM core
  Process(s_axi_aclk)
  begin

    if s_axi_aclk'event and s_axi_aclk = '1' then

      text_done <= '0';
      tag_done <= '0';
      axis_ready <= '0';

      if s_valid = '1' then
        r_out_data <= s_data;
        text_done <= '1';
      end if;

      if s_tag_en = '1' then    
        r_out_tag <= s_tag;
        tag_done <= '1';
      end if;

      if s_s_ready = '1' then
        axis_ready <= '1';
      end if;
      
    end if;
  
  End Process;

end architecture;
