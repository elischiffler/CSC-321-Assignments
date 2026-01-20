import matplotlib.pyplot as plt

# ---- AES data (kB/s) ----
block_sizes = [16, 64, 256, 1024, 8192, 16384]

aes128 = [1097253.02, 1378531.84, 1201933.06, 1208618.67, 1193129.30, 1186376.36]
aes192 = [834354.35, 981999.77, 1009282.99, 1015186.77, 1212268.54, 1227096.06]
aes256 = [738246.28, 868023.36, 892059.39, 866032.64, 920526.85, 1061781.50]

plt.figure()
plt.plot(block_sizes, aes128, marker="o", label="AES-128-CBC")
plt.plot(block_sizes, aes192, marker="o", label="AES-192-CBC")
plt.plot(block_sizes, aes256, marker="o", label="AES-256-CBC")
plt.xscale("log", base=2)
plt.xlabel("Block size (bytes)")
plt.ylabel("Throughput (kB/s)")
plt.title("AES-CBC Throughput vs Block Size (OpenSSL)")
plt.legend()
plt.tight_layout()
plt.savefig("aes_throughput.png", dpi=200)

# ---- RSA data (ops/sec) ----
rsa_bits = [1024, 2048, 3072, 4096]
rsa_sign = [10500.3, 1309.3, 422.0, 186.7]
rsa_verify = [170911.7, 43393.7, 20598.3, 11642.3]

plt.figure()
plt.plot(rsa_bits, rsa_sign, marker="o", label="RSA sign/s")
plt.plot(rsa_bits, rsa_verify, marker="o", label="RSA verify/s")
plt.xlabel("RSA key size (bits)")
plt.ylabel("Operations per second")
plt.title("RSA Performance vs Key Size (OpenSSL)")
plt.legend()
plt.tight_layout()
plt.savefig("rsa_ops.png", dpi=200)

print("Graphs generated successfully.")
