// ============================================================================
//  GOST R 34.12-2015 (Kuznechik) Cipher Core - corrected
//  Full implementation (S-boxes, GF multiplication, R / inv_R, L / inv_L)
//  Fixed key schedule and correct encryption/decryption order.
// ============================================================================

module GOST_cipher (
    input         clk,
    input         rst,
    input         start,
    input  [255:0] master_key,
    input  [127:0] data_in,
    input         mode,       // 0 = encrypt, 1 = decrypt
    output reg [127:0] data_out,
    output reg    ready
);

    reg [127:0] round_keys [0:9];
    reg [3:0]   round;
    reg [127:0] state;
    reg busy;

    // ---------------- S-box (forward) ----------------
    function [7:0] S_box;
        input [7:0] in;
        begin
            case (in)
8'h00: S_box = 8'hFC; 8'h01: S_box = 8'hEE; 8'h02: S_box = 8'hDD; 8'h03: S_box = 8'h11; 
8'h04: S_box = 8'hCF; 8'h05: S_box = 8'h6E; 8'h06: S_box = 8'h31; 8'h07: S_box = 8'h16; 
8'h08: S_box = 8'hFB; 8'h09: S_box = 8'hC4; 8'h0A: S_box = 8'hFA; 8'h0B: S_box = 8'hDA; 
8'h0C: S_box = 8'h23; 8'h0D: S_box = 8'hC5; 8'h0E: S_box = 8'h04; 8'h0F: S_box = 8'h4D; 
8'h10: S_box = 8'hE9; 8'h11: S_box = 8'h77; 8'h12: S_box = 8'hF0; 8'h13: S_box = 8'hDB; 
8'h14: S_box = 8'h93; 8'h15: S_box = 8'h2E; 8'h16: S_box = 8'h99; 8'h17: S_box = 8'hBA; 
8'h18: S_box = 8'h17; 8'h19: S_box = 8'h36; 8'h1A: S_box = 8'hF1; 8'h1B: S_box = 8'hBB; 
8'h1C: S_box = 8'h14; 8'h1D: S_box = 8'hCD; 8'h1E: S_box = 8'h5F; 8'h1F: S_box = 8'hC1; 
8'h20: S_box = 8'hF9; 8'h21: S_box = 8'h18; 8'h22: S_box = 8'h65; 8'h23: S_box = 8'h5A; 
8'h24: S_box = 8'hE2; 8'h25: S_box = 8'h5C; 8'h26: S_box = 8'hEF; 8'h27: S_box = 8'h21; 
8'h28: S_box = 8'h81; 8'h29: S_box = 8'h1C; 8'h2A: S_box = 8'h3C; 8'h2B: S_box = 8'h42; 
8'h2C: S_box = 8'h8B; 8'h2D: S_box = 8'h01; 8'h2E: S_box = 8'h8E; 8'h2F: S_box = 8'h4F; 
8'h30: S_box = 8'h05; 8'h31: S_box = 8'h84; 8'h32: S_box = 8'h02; 8'h33: S_box = 8'hAE; 
8'h34: S_box = 8'hE3; 8'h35: S_box = 8'h6A; 8'h36: S_box = 8'h8F; 8'h37: S_box = 8'hA0; 
8'h38: S_box = 8'h06; 8'h39: S_box = 8'h0B; 8'h3A: S_box = 8'hED; 8'h3B: S_box = 8'h98; 
8'h3C: S_box = 8'h7F; 8'h3D: S_box = 8'hD4; 8'h3E: S_box = 8'hD3; 8'h3F: S_box = 8'h1F; 
8'h40: S_box = 8'hEB; 8'h41: S_box = 8'h34; 8'h42: S_box = 8'h2C; 8'h43: S_box = 8'h51; 
8'h44: S_box = 8'hEA; 8'h45: S_box = 8'hC8; 8'h46: S_box = 8'h48; 8'h47: S_box = 8'hAB; 
8'h48: S_box = 8'hF2; 8'h49: S_box = 8'h2A; 8'h4A: S_box = 8'h68; 8'h4B: S_box = 8'hA2; 
8'h4C: S_box = 8'hFD; 8'h4D: S_box = 8'h3A; 8'h4E: S_box = 8'hCE; 8'h4F: S_box = 8'hCC; 
8'h50: S_box = 8'hB5; 8'h51: S_box = 8'h70; 8'h52: S_box = 8'h0E; 8'h53: S_box = 8'h56; 
8'h54: S_box = 8'h08; 8'h55: S_box = 8'h0C; 8'h56: S_box = 8'h76; 8'h57: S_box = 8'h12; 
8'h58: S_box = 8'hBF; 8'h59: S_box = 8'h72; 8'h5A: S_box = 8'h13; 8'h5B: S_box = 8'h47; 
8'h5C: S_box = 8'h9C; 8'h5D: S_box = 8'hB7; 8'h5E: S_box = 8'h5D; 8'h5F: S_box = 8'h87; 
8'h60: S_box = 8'h15; 8'h61: S_box = 8'hA1; 8'h62: S_box = 8'h96; 8'h63: S_box = 8'h29; 
8'h64: S_box = 8'h10; 8'h65: S_box = 8'h7B; 8'h66: S_box = 8'h9A; 8'h67: S_box = 8'hC7; 
8'h68: S_box = 8'hF3; 8'h69: S_box = 8'h91; 8'h6A: S_box = 8'h78; 8'h6B: S_box = 8'h6F; 
8'h6C: S_box = 8'h9D; 8'h6D: S_box = 8'h9E; 8'h6E: S_box = 8'hB2; 8'h6F: S_box = 8'hB1; 
8'h70: S_box = 8'h32; 8'h71: S_box = 8'h75; 8'h72: S_box = 8'h19; 8'h73: S_box = 8'h3D; 
8'h74: S_box = 8'hFF; 8'h75: S_box = 8'h35; 8'h76: S_box = 8'h8A; 8'h77: S_box = 8'h7E; 
8'h78: S_box = 8'h6D; 8'h79: S_box = 8'h54; 8'h7A: S_box = 8'hC6; 8'h7B: S_box = 8'h80; 
8'h7C: S_box = 8'hC3; 8'h7D: S_box = 8'hBD; 8'h7E: S_box = 8'h0D; 8'h7F: S_box = 8'h57; 
8'h80: S_box = 8'hDF; 8'h81: S_box = 8'hF5; 8'h82: S_box = 8'h24; 8'h83: S_box = 8'hA9; 
8'h84: S_box = 8'h3E; 8'h85: S_box = 8'hA8; 8'h86: S_box = 8'h43; 8'h87: S_box = 8'hC9; 
8'h88: S_box = 8'hD7; 8'h89: S_box = 8'h79; 8'h8A: S_box = 8'hD6; 8'h8B: S_box = 8'hF6; 
8'h8C: S_box = 8'h7C; 8'h8D: S_box = 8'h22; 8'h8E: S_box = 8'hB9; 8'h8F: S_box = 8'h03; 
8'h90: S_box = 8'hE0; 8'h91: S_box = 8'h0F; 8'h92: S_box = 8'hEC; 8'h93: S_box = 8'hDE; 
8'h94: S_box = 8'h7A; 8'h95: S_box = 8'h94; 8'h96: S_box = 8'hB0; 8'h97: S_box = 8'hBC; 
8'h98: S_box = 8'hDC; 8'h99: S_box = 8'hE8; 8'h9A: S_box = 8'h28; 8'h9B: S_box = 8'h50; 
8'h9C: S_box = 8'h4E; 8'h9D: S_box = 8'h33; 8'h9E: S_box = 8'h0A; 8'h9F: S_box = 8'h4A; 
8'hA0: S_box = 8'hA7; 8'hA1: S_box = 8'h97; 8'hA2: S_box = 8'h60; 8'hA3: S_box = 8'h73; 
8'hA4: S_box = 8'h1E; 8'hA5: S_box = 8'h00; 8'hA6: S_box = 8'h62; 8'hA7: S_box = 8'h44; 
8'hA8: S_box = 8'h1A; 8'hA9: S_box = 8'hB8; 8'hAA: S_box = 8'h38; 8'hAB: S_box = 8'h82; 
8'hAC: S_box = 8'h64; 8'hAD: S_box = 8'h9F; 8'hAE: S_box = 8'h26; 8'hAF: S_box = 8'h41; 
8'hB0: S_box = 8'hAD; 8'hB1: S_box = 8'h45; 8'hB2: S_box = 8'h46; 8'hB3: S_box = 8'h92; 
8'hB4: S_box = 8'h27; 8'hB5: S_box = 8'h5E; 8'hB6: S_box = 8'h55; 8'hB7: S_box = 8'h2F; 
8'hB8: S_box = 8'h8C; 8'hB9: S_box = 8'hA3; 8'hBA: S_box = 8'hA5; 8'hBB: S_box = 8'h7D; 
8'hBC: S_box = 8'h69; 8'hBD: S_box = 8'hD5; 8'hBE: S_box = 8'h95; 8'hBF: S_box = 8'h3B; 
8'hC0: S_box = 8'h07; 8'hC1: S_box = 8'h58; 8'hC2: S_box = 8'hB3; 8'hC3: S_box = 8'h40; 
8'hC4: S_box = 8'h86; 8'hC5: S_box = 8'hAC; 8'hC6: S_box = 8'h1D; 8'hC7: S_box = 8'hF7; 
8'hC8: S_box = 8'h30; 8'hC9: S_box = 8'h37; 8'hCA: S_box = 8'h6B; 8'hCB: S_box = 8'hE4; 
8'hCC: S_box = 8'h88; 8'hCD: S_box = 8'hD9; 8'hCE: S_box = 8'hE7; 8'hCF: S_box = 8'h89; 
8'hD0: S_box = 8'hE1; 8'hD1: S_box = 8'h1B; 8'hD2: S_box = 8'h83; 8'hD3: S_box = 8'h49; 
8'hD4: S_box = 8'h4C; 8'hD5: S_box = 8'h3F; 8'hD6: S_box = 8'hF8; 8'hD7: S_box = 8'hFE; 
8'hD8: S_box = 8'h8D; 8'hD9: S_box = 8'h53; 8'hDA: S_box = 8'hAA; 8'hDB: S_box = 8'h90; 
8'hDC: S_box = 8'hCA; 8'hDD: S_box = 8'hD8; 8'hDE: S_box = 8'h85; 8'hDF: S_box = 8'h61; 
8'hE0: S_box = 8'h20; 8'hE1: S_box = 8'h71; 8'hE2: S_box = 8'h67; 8'hE3: S_box = 8'hA4; 
8'hE4: S_box = 8'h2D; 8'hE5: S_box = 8'h2B; 8'hE6: S_box = 8'h09; 8'hE7: S_box = 8'h5B; 
8'hE8: S_box = 8'hCB; 8'hE9: S_box = 8'h9B; 8'hEA: S_box = 8'h25; 8'hEB: S_box = 8'hD0; 
8'hEC: S_box = 8'hBE; 8'hED: S_box = 8'hE5; 8'hEE: S_box = 8'h6C; 8'hEF: S_box = 8'h52; 
8'hF0: S_box = 8'h59; 8'hF1: S_box = 8'hA6; 8'hF2: S_box = 8'h74; 8'hF3: S_box = 8'hD2; 
8'hF4: S_box = 8'hE6; 8'hF5: S_box = 8'hF4; 8'hF6: S_box = 8'hB4; 8'hF7: S_box = 8'hC0; 
8'hF8: S_box = 8'hD1; 8'hF9: S_box = 8'h66; 8'hFA: S_box = 8'hAF; 8'hFB: S_box = 8'hC2; 
8'hFC: S_box = 8'h39; 8'hFD: S_box = 8'h4B; 8'hFE: S_box = 8'h63; 8'hFF: S_box = 8'hB6; 
            endcase
        end
    endfunction

    // ---------------- inverse S-box ----------------
    function [7:0] inv_S_box;
        input [7:0] in;
        begin
            case (in)
8'h00: inv_S_box = 8'hA5; 8'h01: inv_S_box = 8'h2D; 8'h02: inv_S_box = 8'h32; 8'h03: inv_S_box = 8'h8F; 
8'h04: inv_S_box = 8'h0E; 8'h05: inv_S_box = 8'h30; 8'h06: inv_S_box = 8'h38; 8'h07: inv_S_box = 8'hC0; 
8'h08: inv_S_box = 8'h54; 8'h09: inv_S_box = 8'hE6; 8'h0A: inv_S_box = 8'h9E; 8'h0B: inv_S_box = 8'h39; 
8'h0C: inv_S_box = 8'h55; 8'h0D: inv_S_box = 8'h7E; 8'h0E: inv_S_box = 8'h52; 8'h0F: inv_S_box = 8'h91; 
8'h10: inv_S_box = 8'h64; 8'h11: inv_S_box = 8'h03; 8'h12: inv_S_box = 8'h57; 8'h13: inv_S_box = 8'h5A; 
8'h14: inv_S_box = 8'h1C; 8'h15: inv_S_box = 8'h60; 8'h16: inv_S_box = 8'h07; 8'h17: inv_S_box = 8'h18; 
8'h18: inv_S_box = 8'h21; 8'h19: inv_S_box = 8'h72; 8'h1A: inv_S_box = 8'hA8; 8'h1B: inv_S_box = 8'hD1; 
8'h1C: inv_S_box = 8'h29; 8'h1D: inv_S_box = 8'hC6; 8'h1E: inv_S_box = 8'hA4; 8'h1F: inv_S_box = 8'h3F; 
8'h20: inv_S_box = 8'hE0; 8'h21: inv_S_box = 8'h27; 8'h22: inv_S_box = 8'h8D; 8'h23: inv_S_box = 8'h0C; 
8'h24: inv_S_box = 8'h82; 8'h25: inv_S_box = 8'hEA; 8'h26: inv_S_box = 8'hAE; 8'h27: inv_S_box = 8'hB4; 
8'h28: inv_S_box = 8'h9A; 8'h29: inv_S_box = 8'h63; 8'h2A: inv_S_box = 8'h49; 8'h2B: inv_S_box = 8'hE5; 
8'h2C: inv_S_box = 8'h42; 8'h2D: inv_S_box = 8'hE4; 8'h2E: inv_S_box = 8'h15; 8'h2F: inv_S_box = 8'hB7; 
8'h30: inv_S_box = 8'hC8; 8'h31: inv_S_box = 8'h06; 8'h32: inv_S_box = 8'h70; 8'h33: inv_S_box = 8'h9D; 
8'h34: inv_S_box = 8'h41; 8'h35: inv_S_box = 8'h75; 8'h36: inv_S_box = 8'h19; 8'h37: inv_S_box = 8'hC9; 
8'h38: inv_S_box = 8'hAA; 8'h39: inv_S_box = 8'hFC; 8'h3A: inv_S_box = 8'h4D; 8'h3B: inv_S_box = 8'hBF; 
8'h3C: inv_S_box = 8'h2A; 8'h3D: inv_S_box = 8'h73; 8'h3E: inv_S_box = 8'h84; 8'h3F: inv_S_box = 8'hD5; 
8'h40: inv_S_box = 8'hC3; 8'h41: inv_S_box = 8'hAF; 8'h42: inv_S_box = 8'h2B; 8'h43: inv_S_box = 8'h86; 
8'h44: inv_S_box = 8'hA7; 8'h45: inv_S_box = 8'hB1; 8'h46: inv_S_box = 8'hB2; 8'h47: inv_S_box = 8'h5B; 
8'h48: inv_S_box = 8'h46; 8'h49: inv_S_box = 8'hD3; 8'h4A: inv_S_box = 8'h9F; 8'h4B: inv_S_box = 8'hFD; 
8'h4C: inv_S_box = 8'hD4; 8'h4D: inv_S_box = 8'h0F; 8'h4E: inv_S_box = 8'h9C; 8'h4F: inv_S_box = 8'h2F; 
8'h50: inv_S_box = 8'h9B; 8'h51: inv_S_box = 8'h43; 8'h52: inv_S_box = 8'hEF; 8'h53: inv_S_box = 8'hD9; 
8'h54: inv_S_box = 8'h79; 8'h55: inv_S_box = 8'hB6; 8'h56: inv_S_box = 8'h53; 8'h57: inv_S_box = 8'h7F; 
8'h58: inv_S_box = 8'hC1; 8'h59: inv_S_box = 8'hF0; 8'h5A: inv_S_box = 8'h23; 8'h5B: inv_S_box = 8'hE7; 
8'h5C: inv_S_box = 8'h25; 8'h5D: inv_S_box = 8'h5E; 8'h5E: inv_S_box = 8'hB5; 8'h5F: inv_S_box = 8'h1E; 
8'h60: inv_S_box = 8'hA2; 8'h61: inv_S_box = 8'hDF; 8'h62: inv_S_box = 8'hA6; 8'h63: inv_S_box = 8'hFE; 
8'h64: inv_S_box = 8'hAC; 8'h65: inv_S_box = 8'h22; 8'h66: inv_S_box = 8'hF9; 8'h67: inv_S_box = 8'hE2; 
8'h68: inv_S_box = 8'h4A; 8'h69: inv_S_box = 8'hBC; 8'h6A: inv_S_box = 8'h35; 8'h6B: inv_S_box = 8'hCA; 
8'h6C: inv_S_box = 8'hEE; 8'h6D: inv_S_box = 8'h78; 8'h6E: inv_S_box = 8'h05; 8'h6F: inv_S_box = 8'h6B; 
8'h70: inv_S_box = 8'h51; 8'h71: inv_S_box = 8'hE1; 8'h72: inv_S_box = 8'h59; 8'h73: inv_S_box = 8'hA3; 
8'h74: inv_S_box = 8'hF2; 8'h75: inv_S_box = 8'h71; 8'h76: inv_S_box = 8'h56; 8'h77: inv_S_box = 8'h11; 
8'h78: inv_S_box = 8'h6A; 8'h79: inv_S_box = 8'h89; 8'h7A: inv_S_box = 8'h94; 8'h7B: inv_S_box = 8'h65; 
8'h7C: inv_S_box = 8'h8C; 8'h7D: inv_S_box = 8'hBB; 8'h7E: inv_S_box = 8'h77; 8'h7F: inv_S_box = 8'h3C; 
8'h80: inv_S_box = 8'h7B; 8'h81: inv_S_box = 8'h28; 8'h82: inv_S_box = 8'hAB; 8'h83: inv_S_box = 8'hD2; 
8'h84: inv_S_box = 8'h31; 8'h85: inv_S_box = 8'hDE; 8'h86: inv_S_box = 8'hC4; 8'h87: inv_S_box = 8'h5F; 
8'h88: inv_S_box = 8'hCC; 8'h89: inv_S_box = 8'hCF; 8'h8A: inv_S_box = 8'h76; 8'h8B: inv_S_box = 8'h2C; 
8'h8C: inv_S_box = 8'hB8; 8'h8D: inv_S_box = 8'hD8; 8'h8E: inv_S_box = 8'h2E; 8'h8F: inv_S_box = 8'h36; 
8'h90: inv_S_box = 8'hDB; 8'h91: inv_S_box = 8'h69; 8'h92: inv_S_box = 8'hB3; 8'h93: inv_S_box = 8'h14; 
8'h94: inv_S_box = 8'h95; 8'h95: inv_S_box = 8'hBE; 8'h96: inv_S_box = 8'h62; 8'h97: inv_S_box = 8'hA1; 
8'h98: inv_S_box = 8'h3B; 8'h99: inv_S_box = 8'h16; 8'h9A: inv_S_box = 8'h66; 8'h9B: inv_S_box = 8'hE9; 
8'h9C: inv_S_box = 8'h5C; 8'h9D: inv_S_box = 8'h6C; 8'h9E: inv_S_box = 8'h6D; 8'h9F: inv_S_box = 8'hAD; 
8'hA0: inv_S_box = 8'h37; 8'hA1: inv_S_box = 8'h61; 8'hA2: inv_S_box = 8'h4B; 8'hA3: inv_S_box = 8'hB9; 
8'hA4: inv_S_box = 8'hE3; 8'hA5: inv_S_box = 8'hBA; 8'hA6: inv_S_box = 8'hF1; 8'hA7: inv_S_box = 8'hA0; 
8'hA8: inv_S_box = 8'h85; 8'hA9: inv_S_box = 8'h83; 8'hAA: inv_S_box = 8'hDA; 8'hAB: inv_S_box = 8'h47; 
8'hAC: inv_S_box = 8'hC5; 8'hAD: inv_S_box = 8'hB0; 8'hAE: inv_S_box = 8'h33; 8'hAF: inv_S_box = 8'hFA; 
8'hB0: inv_S_box = 8'h96; 8'hB1: inv_S_box = 8'h6F; 8'hB2: inv_S_box = 8'h6E; 8'hB3: inv_S_box = 8'hC2; 
8'hB4: inv_S_box = 8'hF6; 8'hB5: inv_S_box = 8'h50; 8'hB6: inv_S_box = 8'hFF; 8'hB7: inv_S_box = 8'h5D; 
8'hB8: inv_S_box = 8'hA9; 8'hB9: inv_S_box = 8'h8E; 8'hBA: inv_S_box = 8'h17; 8'hBB: inv_S_box = 8'h1B; 
8'hBC: inv_S_box = 8'h97; 8'hBD: inv_S_box = 8'h7D; 8'hBE: inv_S_box = 8'hEC; 8'hBF: inv_S_box = 8'h58; 
8'hC0: inv_S_box = 8'hF7; 8'hC1: inv_S_box = 8'h1F; 8'hC2: inv_S_box = 8'hFB; 8'hC3: inv_S_box = 8'h7C; 
8'hC4: inv_S_box = 8'h09; 8'hC5: inv_S_box = 8'h0D; 8'hC6: inv_S_box = 8'h7A; 8'hC7: inv_S_box = 8'h67; 
8'hC8: inv_S_box = 8'h45; 8'hC9: inv_S_box = 8'h87; 8'hCA: inv_S_box = 8'hDC; 8'hCB: inv_S_box = 8'hE8; 
8'hCC: inv_S_box = 8'h4F; 8'hCD: inv_S_box = 8'h1D; 8'hCE: inv_S_box = 8'h4E; 8'hCF: inv_S_box = 8'h04; 
8'hD0: inv_S_box = 8'hEB; 8'hD1: inv_S_box = 8'hF8; 8'hD2: inv_S_box = 8'hF3; 8'hD3: inv_S_box = 8'h3E; 
8'hD4: inv_S_box = 8'h3D; 8'hD5: inv_S_box = 8'hBD; 8'hD6: inv_S_box = 8'h8A; 8'hD7: inv_S_box = 8'h88; 
8'hD8: inv_S_box = 8'hDD; 8'hD9: inv_S_box = 8'hCD; 8'hDA: inv_S_box = 8'h0B; 8'hDB: inv_S_box = 8'h13; 
8'hDC: inv_S_box = 8'h98; 8'hDD: inv_S_box = 8'h02; 8'hDE: inv_S_box = 8'h93; 8'hDF: inv_S_box = 8'h80; 
8'hE0: inv_S_box = 8'h90; 8'hE1: inv_S_box = 8'hD0; 8'hE2: inv_S_box = 8'h24; 8'hE3: inv_S_box = 8'h34; 
8'hE4: inv_S_box = 8'hCB; 8'hE5: inv_S_box = 8'hED; 8'hE6: inv_S_box = 8'hF4; 8'hE7: inv_S_box = 8'hCE; 
8'hE8: inv_S_box = 8'h99; 8'hE9: inv_S_box = 8'h10; 8'hEA: inv_S_box = 8'h44; 8'hEB: inv_S_box = 8'h40; 
8'hEC: inv_S_box = 8'h92; 8'hED: inv_S_box = 8'h3A; 8'hEE: inv_S_box = 8'h01; 8'hEF: inv_S_box = 8'h26; 
8'hF0: inv_S_box = 8'h12; 8'hF1: inv_S_box = 8'h1A; 8'hF2: inv_S_box = 8'h48; 8'hF3: inv_S_box = 8'h68; 
8'hF4: inv_S_box = 8'hF5; 8'hF5: inv_S_box = 8'h81; 8'hF6: inv_S_box = 8'h8B; 8'hF7: inv_S_box = 8'hC7; 
8'hF8: inv_S_box = 8'hD6; 8'hF9: inv_S_box = 8'h20; 8'hFA: inv_S_box = 8'h0A; 8'hFB: inv_S_box = 8'h08; 
8'hFC: inv_S_box = 8'h00; 8'hFD: inv_S_box = 8'h4C; 8'hFE: inv_S_box = 8'hD7; 8'hFF: inv_S_box = 8'h74; 
            endcase
        end
    endfunction

    // ---------------- GF(2^8) multiplication ----------------
    function [7:0] gf_mul;
        input [7:0] a;
        input [7:0] b;
        integer i;
        reg [7:0] aa;
        reg [7:0] bb;
        reg [7:0] res;
        begin
            aa = a;
            bb = b;
            res = 8'h00;
            for (i = 0; i < 8; i = i + 1) begin
                if (bb[0]) res = res ^ aa;
                bb = bb >> 1;
                if (aa[7]) aa = (aa << 1) ^ 8'hC3;
                else aa = aa << 1;
            end
            gf_mul = res;
        end
    endfunction

    // ---------------- R transformation ----------------
    function [127:0] R_transform;
        input [127:0] data;
        integer i;
        reg [7:0] bytes [0:15];
        reg [7:0] outb [0:15];
        reg [7:0] gamma;
        reg [7:0] coef [0:15];
        begin
            coef[0]=8'h94; coef[1]=8'h20; coef[2]=8'h85; coef[3]=8'h10;
            coef[4]=8'hC2; coef[5]=8'hC0; coef[6]=8'h01; coef[7]=8'hFB;
            coef[8]=8'h01; coef[9]=8'hC0; coef[10]=8'hC2; coef[11]=8'h10;
            coef[12]=8'h85; coef[13]=8'h20; coef[14]=8'h94; coef[15]=8'h01;

            for (i = 0; i < 16; i = i + 1)
                bytes[i] = data[127 - i*8 -: 8];

            gamma = 8'h00;
            for (i = 0; i < 16; i = i + 1)
                gamma = gamma ^ gf_mul(bytes[i], coef[i]);

            outb[0] = gamma;
            for (i = 1; i < 16; i = i + 1)
                outb[i] = bytes[i-1];

            R_transform = {outb[0], outb[1], outb[2], outb[3],
                           outb[4], outb[5], outb[6], outb[7],
                           outb[8], outb[9], outb[10], outb[11],
                           outb[12], outb[13], outb[14], outb[15]};
        end
    endfunction

    // ---------------- inverse R ----------------
    function [127:0] inv_R_transform;
        input [127:0] data;
        integer i;
        reg [7:0] y [0:15];
        reg [7:0] a [0:15];
        reg [7:0] xor_sum;
        reg [7:0] coef [0:15];
        begin
            coef[0]=8'h94; coef[1]=8'h20; coef[2]=8'h85; coef[3]=8'h10;
            coef[4]=8'hC2; coef[5]=8'hC0; coef[6]=8'h01; coef[7]=8'hFB;
            coef[8]=8'h01; coef[9]=8'hC0; coef[10]=8'hC2; coef[11]=8'h10;
            coef[12]=8'h85; coef[13]=8'h20; coef[14]=8'h94; coef[15]=8'h01;

            for (i = 0; i < 16; i = i + 1)
                y[i] = data[127 - i*8 -: 8];

            for (i = 0; i < 15; i = i + 1)
                a[i] = y[i+1];

            xor_sum = 8'h00;
            for (i = 0; i < 15; i = i + 1)
                xor_sum = xor_sum ^ gf_mul(a[i], coef[i]);

            a[15] = y[0] ^ xor_sum;

            inv_R_transform = {a[0], a[1], a[2], a[3],
                               a[4], a[5], a[6], a[7],
                               a[8], a[9], a[10], a[11],
                               a[12], a[13], a[14], a[15]};
        end
    endfunction

    // ---------------- L and inv_L ----------------
    function [127:0] L_transform;
        input [127:0] data;
        integer i;
        reg [127:0] tmp;
        begin
            tmp = data;
            for (i = 0; i < 16; i = i + 1)
                tmp = R_transform(tmp);
            L_transform = tmp;
        end
    endfunction

    function [127:0] inv_L_transform;
        input [127:0] data;
        integer i;
        reg [127:0] tmp;
        begin
            tmp = data;
            for (i = 0; i < 16; i = i + 1)
                tmp = inv_R_transform(tmp);
            inv_L_transform = tmp;
        end
    endfunction

    // ---------------- Key schedule ----------------
    task key_expansion;
        input [255:0] master_key;
        integer i, j, idx;
        reg [127:0] temp;
        reg [127:0] cst [0:31];
        reg [127:0] a, b;
        begin
            round_keys[0] = master_key[255:128];
            round_keys[1] = master_key[127:0];

            for (i = 0; i < 32; i = i + 1) begin
                temp = 128'b0;
                temp[7:0] = i + 1;
                cst[i] = L_transform(temp);
            end

            a = round_keys[0];
            b = round_keys[1];

            for (i = 0; i < 4; i = i + 1) begin
                for (j = 0; j < 8; j = j + 1) begin
                    idx = i*8 + j;
                    temp = a ^ cst[idx];
                    // apply S to each byte
                    temp = {S_box(temp[127:120]), S_box(temp[119:112]),
                            S_box(temp[111:104]), S_box(temp[103:96]),
                            S_box(temp[95:88]),  S_box(temp[87:80]),
                            S_box(temp[79:72]),  S_box(temp[71:64]),
                            S_box(temp[63:56]),  S_box(temp[55:48]),
                            S_box(temp[47:40]),  S_box(temp[39:32]),
                            S_box(temp[31:24]),  S_box(temp[23:16]),
                            S_box(temp[15:8]),   S_box(temp[7:0])};
                    temp = L_transform(temp);
                    temp = temp ^ b;
                    b = a;
                    a = temp;
                end
                round_keys[2*i + 2] = a;
                round_keys[2*i + 3] = b;
            end
        end
    endtask

    // ---------------- Encryption/Decryption primitives ----------------
    function [127:0] E_round;
        input [127:0] in;
        input [127:0] rk;
        reg [127:0] t;
        begin
            t = in ^ rk;
            t = {S_box(t[127:120]), S_box(t[119:112]), S_box(t[111:104]), S_box(t[103:96]),
                 S_box(t[95:88]),  S_box(t[87:80]),  S_box(t[79:72]),  S_box(t[71:64]),
                 S_box(t[63:56]),  S_box(t[55:48]),  S_box(t[47:40]),  S_box(t[39:32]),
                 S_box(t[31:24]),  S_box(t[23:16]),  S_box(t[15:8]),   S_box(t[7:0])};
            E_round = L_transform(t);
        end
    endfunction

    function [127:0] D_round;
        input [127:0] in;
        input [127:0] rk;
        reg [127:0] t;
        begin
            // inverse of: out = L(S(in xor rk)) is: in = S^{-1}(L^{-1}(out)) xor rk
            t = inv_L_transform(in);
            t = {inv_S_box(t[127:120]), inv_S_box(t[119:112]), inv_S_box(t[111:104]), inv_S_box(t[103:96]),
                 inv_S_box(t[95:88]),  inv_S_box(t[87:80]),  inv_S_box(t[79:72]),  inv_S_box(t[71:64]),
                 inv_S_box(t[63:56]),  inv_S_box(t[55:48]),  inv_S_box(t[47:40]),  inv_S_box(t[39:32]),
                 inv_S_box(t[31:24]),  inv_S_box(t[23:16]),  inv_S_box(t[15:8]),   inv_S_box(t[7:0])};
            D_round = t ^ rk;
        end
    endfunction

    // ---------------- Control FSM ----------------
    always @(posedge clk or posedge rst) begin
        if (rst) begin
            ready <= 0;
            busy <= 0;
            round <= 0;
            data_out <= 128'b0;
            state <= 128'b0;
        end else if (start && !busy) begin
            key_expansion(master_key);
            state <= data_in;
            round <= 0;
            busy <= 1;
            ready <= 0;
        end else if (busy) begin
            if (!mode) begin
                // ENCRYPT: apply E_round with K1..K9, then final XOR with K10
                if (round < 9) begin
                    state <= E_round(state, round_keys[round]);
                    round <= round + 1;
                end else begin
                    state <= state ^ round_keys[9];
                    data_out <= state ^ round_keys[9];
                    ready <= 1;
                    busy <= 0;
                end
            end else begin
                // DECRYPT: start with XOR with K10, then apply D_round with K9..K1
                if (round == 0) begin
                    // initial XOR with K10
                    state <= state ^ round_keys[9];
                    round <= 1;
                end else if (round <= 9) begin
                    // apply D_round with key index (9 - (round-1) - 1) => keys 8..0
                    state <= D_round(state, round_keys[9 - round]);
                    round <= round + 1;
                end else begin
                    // after 9 D_rounds, round == 10
                    data_out <= state;
                    ready <= 1;
                    busy <= 0;
                end
            end
        end
    end

endmodule