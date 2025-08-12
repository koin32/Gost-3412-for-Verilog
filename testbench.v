`timescale 1ns/1ps

module tb_gost();

    reg clk;
    reg rst;
    reg start;
    reg mode; // 0 = encrypt, 1 = decrypt
    reg [255:0] master_key;
    reg [127:0] data_in;
    wire [127:0] data_out;
    wire ready;

    integer error_count;

    // Instantiate DUT
    GOST_cipher uut (
        .clk(clk),
        .rst(rst),
        .start(start),
        .master_key(master_key),
        .data_in(data_in),
        .mode(mode),
        .data_out(data_out),
        .ready(ready)
    );

    // Clock generator
    initial clk = 0;
    always #5 clk = ~clk; // 100 MHz

    // Task to wait for ready
    task wait_ready;
        input integer timeout;
        integer i;
        begin
            i = 0;
            while (!ready && i < timeout) begin
                @(posedge clk);
                i = i + 1;
            end
            if (!ready) begin
                $display("ERROR: Simulation timed out after %0d cycles", timeout);
                error_count = error_count + 1;
                $finish;
            end
        end
    endtask

    // Print round keys
    task print_round_keys;
        integer i;
        begin
            $display("Round keys:");
            for (i = 0; i < 10; i = i + 1) begin
                $display("  K%0d = %032x", i+1, uut.round_keys[i]);
            end
        end
    endtask

    // Test vectors from RFC 7801
    localparam [255:0] TEST_KEY_1 =
        256'h8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef;
    localparam [127:0] TEST_PLAIN_1 =
        128'h1122334455667700ffeeddccbbaa9988;
    localparam [127:0] TEST_CIPHER_1 =
        128'h7f679d90bebc24305a468d42b9d4edcd;

    localparam [255:0] TEST_KEY_2 =
        256'h0000000000000000000000000000000000000000000000000000000000000000;
    localparam [127:0] TEST_PLAIN_2 =
        128'h00000000000000000000000000000000;
    localparam [127:0] TEST_CIPHER_2 =
        128'hb66cd8887d38e8d1c147ad4b9d4a08dd;

    // Test procedure
    task run_test;
        input [255:0] key;
        input [127:0] plain;
        input [127:0] cipher;
        input integer test_num;
        begin
            $display("\n=== Test Vector %0d ===", test_num);
            master_key = key;
            data_in = plain;

            $display("Master key:    %064x", master_key);
            $display("Plaintext:     %032x", data_in);
            $display("Expected CT:   %032x", cipher);

            // ENCRYPT
            $display("\n--- ENCRYPTION ---");
            start = 1; mode = 0;
            @(posedge clk);
            start = 0;

            wait_ready(10000); // Timeout after 10000 cycles
            print_round_keys();
            $display("Ciphertext:    %032x", data_out);
            if (data_out !== cipher) begin
                $display("ERROR: Ciphertext does not match expected!");
                error_count = error_count + 1;
            end else begin
                $display("Encryption OK");
            end

            // DECRYPT
            $display("\n--- DECRYPTION ---");
            data_in = cipher;
            start = 1; mode = 1;
            @(posedge clk);
            start = 0;

            wait_ready(10000); // Timeout after 10000 cycles
            $display("Decrypted PT:  %032x", data_out);
            if (data_out !== plain) begin
                $display("ERROR: Decrypted plaintext does not match!");
                error_count = error_count + 1;
            end else begin
                $display("Decryption OK");
            end
        end
    endtask

    initial begin
        error_count = 0;
        $display("======================================");
        $display("   GOST R 34.12-2015 (Kuznechik) Test  ");
        $display("======================================");

        rst = 1; start = 0; mode = 0;
        #20 rst = 0;

        // Run first test vector (RFC 7801)
        run_test(TEST_KEY_1, TEST_PLAIN_1, TEST_CIPHER_1, 1);

        // Run second test vector (all zeros)
        run_test(TEST_KEY_2, TEST_PLAIN_2, TEST_CIPHER_2, 2);

        $display("\nTest completed with %0d error(s)", error_count);
        if (error_count == 0) begin
            $display("All tests PASSED!");
        end else begin
            $display("Tests FAILED!");
        end
        $display("Simulation reached end of testbench");
        $finish;
    end

endmodule