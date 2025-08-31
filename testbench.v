`timescale 1ns/1ps

module tb_kuznyechik;

  reg clk;
  reg rst_n;
  reg start;
  reg mode; // 0=encrypt, 1=decrypt
  reg [255:0] key;
  reg [127:0] block_in;
  wire [127:0] block_out;
  wire busy;
  wire done;

  // Instantiate DUT
  kuznyechik dut (
    .clk(clk),
    .rst_n(rst_n),
    .start(start),
    .mode(mode),
    .key(key),
    .block_in(block_in),
    .block_out(block_out),
    .busy(busy),
    .done(done)
  );

  // Clock generation
  initial begin
    clk = 0;
    forever #5 clk = ~clk; // 100 MHz
  end

  // Reset
  initial begin
    rst_n = 0;
    #20;
    rst_n = 1;
  end

  // Test vectors from GOST R 34.12-2015 (Appendix A.1)
  reg [255:0] test_key;
  reg [127:0] test_plain;
  reg [127:0] test_cipher;

  initial begin
    test_key    = 256'h8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef;
    test_plain  = 128'h1122334455667700ffeeddccbbaa9988;
    test_cipher = 128'h58d57a060a66ebed99b24b840cab785a;

    // Monitor signals
    $monitor("Time=%t, state_reg=%h, ks_busy=%b, done=%b, block_out=%h", $time, dut.state_reg, dut.ks_busy, dut.done, dut.block_out);

    // Wait reset release
    @(posedge rst_n);
    @(posedge clk);

    // Wait for key schedule completion
    $display("Waiting for key schedule...");
    key = test_key;
    block_in = test_plain;
    mode = 0; // encrypt
    start = 1;
    @(posedge clk);
    start = 0;
    wait(dut.ks_busy == 0);
    $display("Key schedule completed. Round keys:");
    for (int i = 0; i < 10; i = i + 1) begin
        $display("rk[%0d] = %h", i, dut.rk[i]);
    end

    // ENCRYPT test
    $display("Starting encryption test...");
    start = 1;
    @(posedge clk);
    start = 0;
    wait(done);
    @(posedge clk);

    if (block_out === test_cipher)
      $display("ENCRYPT PASS: %h", block_out);
    else
      $display("ENCRYPT FAIL: got %h expected %h", block_out, test_cipher);

    // DECRYPT test
    $display("Starting decryption test...");
    block_in = test_cipher;
    mode = 1; // decrypt
    start = 1;
    @(posedge clk);
    start = 0;
    wait(done);
    @(posedge clk);

    if (block_out === test_plain)
      $display("DECRYPT PASS: %h", block_out);
    else
      $display("DECRYPT FAIL: got %h expected %h", block_out, test_plain);

    #100;
    $display("Simulation finished.");
    $finish;
  end
endmodule