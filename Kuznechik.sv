`timescale 1ns/1ps

module kuznyechik (
    input clk,
    input rst_n,
    input start,
    input mode,              // 0 = encrypt, 1 = decrypt
    input [255:0] key,
    input [127:0] block_in,
    output reg [127:0] block_out,
    output reg busy,
    output reg done
);

// -----------------------------------------------------------------------------
// Constants: S-box (flattened) and inverse S-box (flattened)
// -----------------------------------------------------------------------------
localparam [2047:0] SBOX_FLAT = {
    8'hFC,8'hEE,8'hDD,8'h11,8'hCF,8'h6E,8'h31,8'h16,8'hFB,8'hC4,8'hFA,8'hDA,8'h23,8'hC5,8'h04,8'h4D,
    8'hE9,8'h77,8'hF0,8'hDB,8'h93,8'h2E,8'h99,8'hBA,8'h17,8'h36,8'hF1,8'hBB,8'h14,8'hCD,8'h5F,8'hC1,
    8'hF9,8'h18,8'h65,8'h5A,8'hE2,8'h5C,8'hEF,8'h21,8'h81,8'h1C,8'h3C,8'h42,8'h8B,8'h01,8'h8E,8'h4F,
    8'h05,8'h84,8'h02,8'hAE,8'hE3,8'h6A,8'h8F,8'hA0,8'h06,8'h0B,8'hED,8'h98,8'h7F,8'hD4,8'hD3,8'h1F,
    8'hEB,8'h34,8'h2C,8'h51,8'hEA,8'hC8,8'h48,8'hAB,8'hF2,8'h2A,8'h68,8'hA2,8'hFD,8'h3A,8'hCE,8'hCC,
    8'hB5,8'h70,8'h0E,8'h56,8'h08,8'h0C,8'h76,8'h12,8'hBF,8'h72,8'h13,8'h47,8'h9C,8'hB7,8'h5D,8'h87,
    8'h15,8'hA1,8'h96,8'h29,8'h10,8'h7B,8'h9A,8'hC7,8'hF3,8'h91,8'h78,8'h6F,8'h9D,8'h9E,8'hB2,8'hB1,
    8'h32,8'h75,8'h19,8'h3D,8'hFF,8'h35,8'h8A,8'h7E,8'h6D,8'h54,8'hC6,8'h80,8'hC3,8'hBD,8'h0D,8'h57,
    8'hDF,8'hF5,8'h24,8'hA9,8'h3E,8'hA8,8'h43,8'hC9,8'hD7,8'h79,8'hD6,8'hF6,8'h7C,8'h22,8'hB9,8'h03,
    8'hE0,8'h0F,8'hEC,8'hDE,8'h7A,8'h94,8'hB0,8'hBC,8'hDC,8'hE8,8'h28,8'h50,8'h4E,8'h33,8'h0A,8'h4A,
    8'hA7,8'h97,8'h60,8'h73,8'h1E,8'h00,8'h62,8'h44,8'h1A,8'hB8,8'h38,8'h82,8'h64,8'h9F,8'h26,8'h41,
    8'hAD,8'h45,8'h46,8'h92,8'h27,8'h5E,8'h55,8'h2F,8'h8C,8'hA3,8'hA5,8'h7D,8'h69,8'hD5,8'h95,8'h3B,
    8'h07,8'h58,8'hB3,8'h40,8'h86,8'hAC,8'h1D,8'hF7,8'h30,8'h37,8'h6B,8'hE4,8'h88,8'hD9,8'hE7,8'h89,
    8'hE1,8'h1B,8'h83,8'h49,8'h4C,8'h3F,8'hF8,8'hFE,8'h8D,8'h53,8'hAA,8'h90,8'hCA,8'hD8,8'h85,8'h61,
    8'h20,8'h71,8'h67,8'hA4,8'h2D,8'h2B,8'h09,8'h5B,8'hCB,8'h9B,8'h25,8'hD0,8'hBE,8'hE5,8'h6C,8'h52,
    8'h59,8'hA6,8'h74,8'hD2,8'hE6,8'hF4,8'hB4,8'hC0,8'hD1,8'h66,8'hAF,8'hC2,8'h39,8'h4B,8'h63,8'hB6
};

localparam [2047:0] SBOX_INV_FLAT = {
    8'hA5,8'h2D,8'h32,8'h8F,8'h0E,8'h30,8'h38,8'hC0,8'h54,8'hE6,8'h9E,8'h39,8'h55,8'h7E,8'h52,8'h91,
    8'h64,8'h03,8'h57,8'h5A,8'h1C,8'h60,8'h07,8'h18,8'h21,8'h72,8'hA8,8'hD1,8'h29,8'hC6,8'hA4,8'h3F,
    8'hE0,8'h27,8'h8D,8'h0C,8'h82,8'hEA,8'hAE,8'hB4,8'h9A,8'h63,8'h49,8'hE5,8'h42,8'hE4,8'h15,8'hB7,
    8'hC8,8'h06,8'h70,8'h9D,8'h41,8'h75,8'h19,8'hC9,8'hAA,8'hFC,8'h4D,8'hBF,8'h2A,8'h73,8'h84,8'hD5,
    8'hC3,8'hAF,8'h2B,8'h86,8'hA7,8'hB1,8'hB2,8'h5B,8'h46,8'hD3,8'h9F,8'hFD,8'hD4,8'h0F,8'h9C,8'h2F,
    8'h9B,8'h43,8'hEF,8'hD9,8'h79,8'hB6,8'h53,8'h7F,8'hC1,8'hF0,8'h23,8'hE7,8'h25,8'h5E,8'hB5,8'h1E,
    8'hA2,8'hDF,8'hA6,8'hFE,8'hAC,8'h22,8'hF9,8'hE2,8'h4A,8'hBC,8'h35,8'hCA,8'hEE,8'h78,8'h05,8'h6B,
    8'h51,8'hE1,8'h59,8'hA3,8'hF2,8'h71,8'h56,8'h11,8'h6A,8'h89,8'h94,8'h65,8'h8C,8'hBB,8'h77,8'h3C,
    8'h7B,8'h28,8'hAB,8'hD2,8'h31,8'hDE,8'hC4,8'h5F,8'hCC,8'hCF,8'h76,8'h2C,8'hB8,8'hD8,8'h2E,8'h36,
    8'hDB,8'h69,8'hB3,8'h14,8'h95,8'hBE,8'h62,8'hA1,8'h3B,8'h16,8'h66,8'hE9,8'h5C,8'h6C,8'h6D,8'hAD,
    8'h37,8'h61,8'h4B,8'hB9,8'hE3,8'hBA,8'hF1,8'hA0,8'h85,8'h83,8'hDA,8'h47,8'hC5,8'hB0,8'h33,8'hFA,
    8'h96,8'h6F,8'h6E,8'hC2,8'hF6,8'h50,8'hFF,8'h5D,8'hA9,8'h8E,8'h17,8'h1B,8'h97,8'h7D,8'hEC,8'h58,
    8'hF7,8'h1F,8'hFB,8'h7C,8'h09,8'h0D,8'h7A,8'h67,8'h45,8'h87,8'hDC,8'hE8,8'h4F,8'h1D,8'h4E,8'h04,
    8'hEB,8'hF8,8'hF3,8'h3E,8'h3D,8'hBD,8'h8A,8'h88,8'hDD,8'hCD,8'h0B,8'h13,8'h98,8'h02,8'h93,8'h80,
    8'h90,8'hD0,8'h24,8'h34,8'hCB,8'hED,8'hF4,8'hCE,8'h99,8'h10,8'h44,8'h40,8'h92,8'h3A,8'h01,8'h26,
    8'h12,8'h1A,8'h48,8'h68,8'hF5,8'h81,8'h8B,8'hC7,8'hD6,8'h20,8'h0A,8'h08,8'h00,8'h4C,8'hD7,8'h74
};

localparam [127:0] L_VEC = {8'h94,8'h20,8'h85,8'h10,8'hC2,8'hC0,8'h01,8'hFB,8'h01,8'hC0,8'hC2,8'h10,8'h85,8'h20,8'h94,8'h01};

// Helpers: sbox accessor, inverse accessor, GF multiply
function [7:0] sbox;
    input [7:0] inb;
    begin
        sbox = SBOX_FLAT[(255 - inb)*8 +: 8];
    end
endfunction

function [7:0] sbox_inv;
    input [7:0] inb;
    begin
        sbox_inv = SBOX_INV_FLAT[(255 - inb)*8 +: 8];
    end
endfunction

function [7:0] gf_mul;
    input [7:0] a;
    input [7:0] b;
    int i;
    reg [15:0] t;
    begin
        t = 16'd0;
        for (i=0; i<8; i=i+1)
            if (b[i]) t = t ^ (a << i);
        for (i=15; i>=8; i=i-1)
            if (t[i]) t = t ^ (9'h1C3 << (i-8));
        gf_mul = t[7:0];
    end
endfunction

// R transformation and its inverse
function [127:0] R_transform;
    input [127:0] state;
    int i;
    reg [7:0] b [0:15];
    reg [7:0] newb [0:15];
    reg [7:0] acc;
    begin
        for (i=0; i<16; i=i+1) b[i] = state[127-8*i -: 8];
        acc = 8'h00;
        for (i=0; i<16; i=i+1) acc = acc ^ gf_mul(b[i], L_VEC[127-8*i -:8]);
        newb[0] = acc;
        for (i=1; i<16; i=i+1) newb[i] = b[i-1];
        for (i=0; i<16; i=i+1) R_transform[127-8*i -:8] = newb[i];
    end
endfunction

function [127:0] R_inv_transform;
    input [127:0] state;
    int i;
    reg [7:0] nb [0:15];
    reg [7:0] b [0:15];
    reg [7:0] sum;
    begin
        for (i=0; i<16; i=i+1) nb[i] = state[127-8*i -:8];
        for (i=0; i<15; i=i+1) b[i] = nb[i+1];
        sum = 8'h00;
        for (i=0; i<15; i=i+1) sum = sum ^ gf_mul(b[i], L_VEC[127-8*i -:8]);
        b[15] = nb[0] ^ sum;
        for (i=0; i<16; i=i+1) R_inv_transform[127-8*i -:8] = b[i];
    end
endfunction

function [127:0] L_transform;
    input [127:0] state_in;
    int i;
    reg [127:0] s;
    begin
        s = state_in;
        for (i=0; i<16; i=i+1) s = R_transform(s);
        L_transform = s;
    end
endfunction

function [127:0] L_inv_transform;
    input [127:0] state_in;
    int i;
    reg [127:0] s;
    begin
        s = state_in;
        for (i=0; i<16; i=i+1) s = R_inv_transform(s);
        L_inv_transform = s;
    end
endfunction

function [127:0] X_transform;
    input [127:0] a;
    input [127:0] b;
    begin
        X_transform = a ^ b;
    end
endfunction

// Round keys storage
reg [127:0] rk [0:9];
reg [127:0] ks_k1, ks_k2, ks_tmp, ks_C;
reg [5:0] ks_i;
reg [3:0] ks_iter;
reg ks_busy;
reg keys_generated;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        ks_k1 <= 128'h0;
        ks_k2 <= 128'h0;
        ks_tmp <= 128'h0;
        ks_C <= 128'h0;
        ks_i <= 6'h0;
        ks_iter <= 4'h0;
        ks_busy <= 1'b0;
        keys_generated <= 1'b0;
        for (int i = 0; i < 10; i = i + 1) rk[i] <= 128'h0;
    end else if (start && !ks_busy && !busy && !keys_generated) begin
        ks_k1 <= key[255:128];
        ks_k2 <= key[127:0];
        rk[0] <= key[255:128];
        rk[1] <= key[127:0];
        ks_i <= 6'h0;
        ks_iter <= 4'h2;
        ks_busy <= 1'b1;
        //$display("Key schedule start: k1=%h, k2=%h", key[255:128], key[127:0]);
    end else if (ks_busy) begin
        ks_C = 128'h0;
        ks_C[7:0] = ks_i + 1;
        //$display("Iteration %0d: C=%h", ks_i + 1, ks_C);
        ks_C = L_transform(ks_C);
        //$display("Iteration %0d: C after L=%h", ks_i + 1, ks_C);
        ks_tmp = X_transform(ks_k1, ks_C);
        //$display("Iteration %0d: tmp after X=%h", ks_i + 1, ks_tmp);
        ks_tmp = S_transform(ks_tmp);
        //$display("Iteration %0d: tmp after S=%h", ks_i + 1, ks_tmp);
        ks_tmp = L_transform(ks_tmp);
        //$display("Iteration %0d: tmp after L=%h", ks_i + 1, ks_tmp);
        ks_tmp = ks_tmp ^ ks_k2;
        //$display("Iteration %0d: tmp after XOR=%h", ks_i + 1, ks_tmp);
        if (ks_i[0] == 1 && ks_i >= 1 && ks_iter < 10) begin
            rk[ks_iter] <= ks_tmp;
            //$display("Storing rk[%0d]=%h", ks_iter, ks_tmp);
            ks_iter <= ks_iter + 1;
        end
        ks_k2 <= ks_k1;
        ks_k1 <= ks_tmp;
        //$display("Iteration %0d: k1=%h, k2=%h", ks_i + 1, ks_tmp, ks_k1);
        ks_i <= ks_i + 1;
        if (ks_i == 6'd31) begin
            ks_busy <= 1'b0;
            keys_generated <= 1'b1;
        end
    end
end

function [127:0] S_transform;
    input [127:0] state;
    int i;
    reg [127:0] outv;
    begin
        for (i=0; i<16; i=i+1) outv[127-8*i -:8] = sbox(state[127-8*i -:8]);
        S_transform = outv;
    end
endfunction

function [127:0] S_inv_transform;
    input [127:0] state;
    int i;
    reg [127:0] outv;
    begin
        for (i=0; i<16; i=i+1) outv[127-8*i -:8] = sbox_inv(state[127-8*i -:8]);
        S_inv_transform = outv;
    end
endfunction

function [127:0] encrypt_block;
    input [127:0] pt;
    int i;
    reg [127:0] state;
    begin
        state = pt ^ rk[0];
        //$display("Encrypt round 0: state=%h", state);
        for (i=1; i<=9; i=i+1) begin
            state = S_transform(state);
            //$display("Encrypt round %0d after S: %h", i, state);
            state = L_transform(state);
            //$display("Encrypt round %0d after L: %h", i, state);
            state = state ^ rk[i];
            //$display("Encrypt round %0d after X: %h", i, state);
        end
        encrypt_block = state;
    end
endfunction

function [127:0] decrypt_block;
    input [127:0] ct;
    int i;
    reg [127:0] state;
    begin
        state = ct;
        //$display("Decrypt round 9: state=%h", state);
        for (i=9; i>=1; i=i-1) begin
            state = state ^ rk[i];
            //$display("Decrypt round %0d after X: %h", i, state);
            state = L_inv_transform(state);
            //$display("Decrypt round %0d after L_inv: %h", i, state);
            state = S_inv_transform(state);
            //$display("Decrypt round %0d after S_inv: %h", i, state);
        end
        state = state ^ rk[0];
        //$display("Decrypt final: state=%h", state);
        decrypt_block = state;
    end
endfunction

// Простой конечный автомат
reg [1:0] state_reg, state_next;
localparam IDLE = 2'd0, RUN = 2'd1, DONE = 2'd2;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        block_out <= 128'h0;
        busy <= 0;
        done <= 0;
        state_reg <= IDLE;
    end else begin
        state_reg <= state_next;
        case (state_reg)
            IDLE: if (start) begin
                busy <= 1;
                done <= 0;
            end
            RUN: begin
                if (mode == 0) // encrypt
                    block_out <= encrypt_block(block_in);
                else
                    block_out <= decrypt_block(block_in);
                busy <= 0;
                done <= 1;
            end
            DONE: begin
                done <= 0;
            end
        endcase
    end
end

always @(*) begin
    state_next = state_reg;
    case (state_reg)
        IDLE: begin
            if (start && !ks_busy) state_next = RUN;
        end
        RUN: begin
            state_next = DONE;
        end
        DONE: begin
            state_next = IDLE;
        end
    endcase
end

endmodule