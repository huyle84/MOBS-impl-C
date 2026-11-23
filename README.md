# MOBS[ML-DSA] — cài đặt tham chiếu bằng C

Cài đặt đầy đủ lược đồ **MOBS (Modular-Opening Blind Signatures)** theo bản thảo gửi
Computer Standards & Interfaces (`MOBS-CSI-23-11-2026-v2`), với:

* **Người ký dùng ML-DSA (FIPS 204) nguyên bản**: ký mù 2 lượt, người ký chỉ nhận
  một chuỗi 32/48/64 byte `C = SHAKE256(DS_com‖r‖m)` và trả về đúng một chữ ký
  FIPS 204 trên `DS_iss‖C`. Không có thỏa thuận trước nào về vị trí sẽ mở.
* **Mô-đun mở (opening module)**: từ chữ ký cơ sở, người dùng mở **bất kỳ tập vị trí
  `D` nào** của `m`, bao nhiêu lần cũng được, gắn với ngữ cảnh `ctx`; các lần mở
  không liên kết được với nhau và với phiên ký.
* **NIZK: Ligero** (AHIV17) trên trường Goldilocks, biến thành không tương tác
  bằng biến đổi BCS/Fiat–Shamir với cSHAKE256 — chỉ dựa trên hàm băm, không cần
  trusted setup. Quan hệ chứng minh là (O1)–(O8) của bản thảo. Các cận an toàn
  được chứng minh trong **ROM cổ điển** (Phụ lục A của bản thảo); chưa có chứng
  minh trong QROM.

Ngôn ngữ: **C (C11/gnu11)** — cùng ngôn ngữ với bản cài đặt tham chiếu chính thức
của ML-DSA (pq-crystals/dilithium, nộp cho NIST) và các thư viện đang dùng rộng rãi
(liboqs, PQClean, mldsa-native). Mã ML-DSA được biên dịch **không sửa đổi** từ
`third_party/dilithium` (commit `d35ba3fe`, 03/06/2026, bản FIPS 204 có context
string; hash KAT của cả ba mức khớp `SHA256SUMS` công bố).

> Đây là bản nguyên mẫu nghiên cứu, **chưa được kiểm định (audit)** và **không
> chạy thời gian hằng (not constant-time)** ở phía người chứng minh. Xem
> `DESIGN.md` §5.

## 1. Vì sao chọn Ligero

Định lý của bản thảo cần một NIZK có nhãn (labelled) trong ROM với
**zero-knowledge** (cho blindness và multi-show unlinkability) và **online
simulation-extractability** (cho OMUF-MO), và không dựa trên giả thiết nào ngoài hàm băm và chính ML-DSA (các giả thiết
này được cho là đứng vững trước máy tính lượng tử).
Cột "Trích xuất trực tuyến" dưới đây nói về ROM cổ điển.

| Ứng viên | Chỉ dựa trên hàm băm / không setup | Trích xuất trực tuyến | Phù hợp với quan hệ (~85 % là Keccak) | Độ phức tạp cài đặt | Kích thước chứng minh |
|---|---|---|---|---|---|
| **Ligero + BCS** (chọn) | có / có | có, từ truy vấn Merkle (straight-line); chứng minh ở Phụ lục A của bản thảo | tốt: mạch R1CS tổng quát trên trường 64 bit | thấp: RS code + NTT + Merkle | lớn (vài MiB) |
| VOLE-in-the-head (FAEST-style) | có / có | khả thi (qua truy vấn RO) | rất tốt cho mạch nhị phân | trung bình–cao | nhỏ hơn |
| Sumcheck/GKR + Ligero (Longfellow-zk) | có / có | khả thi (qua truy vấn RO) | tốt, cần mạch phân tầng | cao | nhỏ hơn |
| STARK/FRI (AIR) | có / có | khả thi (qua truy vấn RO) | phải viết lại thành AIR | cao | nhỏ (succinct) |
| NIZK lưới (LNP22, …) | có / có | thường cần rewinding | tốt cho (O5), rất đắt cho SHAKE | cao | phụ thuộc mạnh vào phần Keccak |
| Groth16 / PLONK / Bulletproofs | **không** (pairing/DL) | — | — | — | rất nhỏ |

Ligero là lựa chọn phù hợp nhất cho một **cài đặt tham chiếu tự chứa, kiểm chứng
được**: giả thiết tối thiểu (chỉ hash, cùng họ Keccak với ML-DSA), ZK thống kê,
trích xuất kiểu straight-line tự nhiên của BCS, các khối xây dựng chuẩn mực, và
không phụ thuộc thư viện ngoài. Đổi lại kích thước chứng minh lớn hơn các hệ đã
tối ưu (xem §5). Lớp mạch (`cs_t`) độc lập với hệ chứng minh nên có thể chuyển
sang VOLEitH/Longfellow sau này.

## 2. Cấu trúc thư mục

```
src/
  field.[ch]           trường Goldilocks p = 2^64 − 2^32 + 1, NTT, coset
  cs.[ch]              hệ ràng buộc (nhân x·y = z, ràng buộc tuyến tính)
  gadgets.[ch]         bit, XOR, so sánh hằng, phân tích bit
  keccak_circuit.[ch]  Keccak-f[1600] và SHAKE256 dạng mạch
  mldsa_circuit.[ch]   quan hệ mở (O1)–(O8) của MOBS[ML-DSA]
  ligero.[ch]          Ligero prover/verifier (BCS, Merkle có salt)
  xof.[ch]             cSHAKE256 (SP 800-185) cho random oracle của NIZK
  mobs.[ch]            API MOBS: keygen, user1, sign, user2, open, verify
  mobs_params.h        hằng số, domain separation
tests/                 test_field, test_xof, test_keccak, test_ligero,
                       test_mldsa_circuit{2,3,5}, test_mobs{2,3,5}
examples/demo.c        ví dụ đầy đủ: 6 thuộc tính, hai lần mở khác nhau
bench/bench_mobs.c     đo thời gian/kích thước (in bảng markdown)
third_party/dilithium  ML-DSA tham chiếu (không sửa), license CC0/Apache-2.0
DESIGN.md              đặc tả byte-level, thiết kế mạch, tham số & an toàn
```

## 3. Biên dịch và kiểm thử

Yêu cầu: GCC hoặc Clang 64-bit (cần `__int128`), `make`, `libm`, OpenMP (mặc định
`OPENMP=1`; `make OPENMP=0` cho bản một luồng). Đã kiểm thử trên Ubuntu 24.04,
GCC 13.3, x86-64 và macOS 26.2, Homebrew GCC 16.2, Apple M2. Trên Windows nên dùng WSL2 (MSVC không hỗ trợ
`__int128`).

```sh
make              # build cho ML-DSA-44/65/87 (mode 2/3/5)
make check        # kiểm thử chức năng (end-to-end dùng tham số Ligero nhỏ, KHÔNG an toàn)
make check-full   # end-to-end với tham số thật, ML-DSA-44 (~1 phút)
./build/test_mobs3 && ./build/test_mobs5   # tham số thật cho ML-DSA-65/87
./build/demo2     # ví dụ (thêm --fast để chạy nhanh với tham số thử)
./build/bench_mobs2 4 8 16 32 64           # benchmark theo n
```

Kết quả hiện tại: toàn bộ `make check` và các bài kiểm thử với
tham số thật cho cả ba mức đều qua; build với AddressSanitizer + UBSan sạch.

Các kiểm tra quan trọng: mạch SHAKE256 khớp `fips202.c`; SampleInBall trong mạch
khớp `poly_challenge`; chữ ký FIPS 204 thật thỏa mạch; giá trị mở sai, khóa công
khai sai, thuộc tính ẩn bị giả mạo, chữ ký hỏng → vi phạm ràng buộc; kiểm tra
khoảng (O8a) đúng tại biên: `z = ±(γ₁−β−1)` được nhận, `z = ±(γ₁−β)` bị từ chối; chứng minh bị
sửa bất kỳ byte nào, sai nhãn `ctx`, sai tập `D`, sai `pk` → bị từ chối; mở toàn
bộ `D=[n]` và mở rỗng `D=∅` đều hoạt động.

## 4. Sử dụng API

```c
#include "mobs.h"   /* biên dịch với -DDILITHIUM_MODE=2|3|5, link build/libmobsX.a -lm */

uint8_t pk[MOBS_PK_BYTES], sk[MOBS_SK_BYTES];
mobs_keygen(pk, sk);                                   /* bên phát hành */

/* ký mù: m là n thuộc tính, mỗi thuộc tính 32 byte */
mobs_user_state_t st; mobs_cred_t cred;
uint8_t rho1[MOBS_RHO1_BYTES], rho2[MOBS_RHO2_BYTES];
mobs_user1(&st, rho1, m, n);                           /* người dùng -> người ký: rho1 = C */
mobs_sign(rho2, rho1, sk);                             /* một lần ML-DSA.Sign chuẩn */
if (mobs_user2(&cred, &st, rho2, pk) != 0) { /* chữ ký không hợp lệ */ }

/* mở các vị trí tùy ý, bất cứ lúc nào, bao nhiêu lần cũng được */
uint8_t dmask[n] = {0}; dmask[3] = 1;                  /* chỉ mở vị trí 3 */
uint8_t *tau; size_t taulen;
mobs_open(&tau, &taulen, &cred, pk, dmask, ctx, ctxlen, NULL);

/* bên kiểm tra: chỉ biết pk, n, D, y_D, ctx */
int ok = mobs_verify(pk, n, dmask, y, ctx, ctxlen, tau, taulen, NULL) == 0;
free(tau);
```

Giá trị trả về: `0` là thành công. `mobs_user2` trả `-1` nếu chữ ký sai, `-2` nếu
`SampleInBall` của chữ ký vượt số khối cho phép (xác suất ≤ 2^−140 với người ký
trung thực). `ctx` nên chứa định danh bên kiểm tra và nonce để chống phát lại.

Tên trong API và trong bản thảo: `rho1` = `msg1` (= `C`), `rho2` = `msg2` (chữ ký
FIPS 204), `tau` = opening `θ`.

Kích thước thông điệp ký: `rho1` = 32/48/64 byte; `rho2` = 2420/3309/4627 byte
(chữ ký FIPS 204); `pk` = 1312/1952/2592 byte.

## 5. Kết quả đo (số liệu dùng trong bản thảo)

Mọi số trong Bảng 5–6 của bản thảo lấy từ các log dưới đây; lệnh chạy lại ở
`REPRODUCE.md`. Cấu hình: n = 8, mở một nửa số vị trí, 10 lần chạy cho mỗi bộ
tham số và mỗi số luồng; trung bình ± độ lệch chuẩn (`bench/stats_threads.py`).

* **Xeon**: máy ảo Ubuntu 24.04, 2 vCPU "Intel Xeon Processor @ 2.10 GHz",
  GCC 13.3 `-O2 -fopenmp`; chạy một luồng thì ghim nhân bằng `taskset -c 0`.
  Log: `bench/results/bench-xeon-2026-11-15.log`, `bench/results/bb26-xeon-2026-11-15.log`.
* **Apple M2**: Mac mini M2 (4 nhân hiệu năng cao + 4 nhân tiết kiệm điện, 16 GB),
  macOS 26.2, chạy trực tiếp, Homebrew GCC 16.2 `-O2 -fopenmp`; macOS không cho
  ghim nhân. Log: `bench/results/bench-m2-macos-2026-11-15.log`,
  `bench/results/bb26-m2-2026-11-15.log`.

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| KeyGen, Xeon / M2 (ms) | 0.10 / 0.047 | 0.18 / 0.088 | 0.25 / 0.129 |
| User₁, Xeon / M2 (ms) | 0.002 / 0.002 | 0.002 / 0.002 | 0.002 / 0.002 |
| Sign (FIPS 204), Xeon / M2 (ms) | 0.39 / 0.22 | 0.59 / 0.37 | 0.79 / 0.43 |
| User₂, Xeon / M2 (ms) | 0.10 / 0.052 | 0.14 / 0.085 | 0.29 / 0.138 |
| Open, Xeon, 1 luồng (s) | 12.09 ± 0.55 | 18.84 ± 0.26 | 29.79 ± 0.92 |
| Open, Xeon, 2 luồng (s) | 6.96 ± 0.33 | 10.69 ± 0.29 | 16.74 ± 0.60 |
| Open, M2, 1 luồng (s) | 3.53 ± 0.03 | 5.00 ± 0.01 | 7.70 ± 0.02 |
| Open, M2, 4 luồng (s) | 1.41 ± 0.01 | 1.98 ± 0.00 | 3.06 ± 0.06 |
| Verify, Xeon, 1 luồng (s) | 7.22 ± 0.38 | 12.67 ± 0.61 | 21.58 ± 0.95 |
| Verify, Xeon, 2 luồng (s) | 4.49 ± 0.17 | 7.92 ± 0.35 | 13.48 ± 0.35 |
| Verify, M2, 1 luồng (s) | 2.07 ± 0.03 | 3.65 ± 0.00 | 6.34 ± 0.03 |
| Verify, M2, 4 luồng (s) | 1.15 ± 0.00 | 2.06 ± 0.00 | 3.66 ± 0.03 |
| Bộ nhớ đỉnh, 1 luồng, Xeon / M2 | 0.74 / 0.81 GiB | 0.77 / 0.91 GiB | 1.02 / 1.13 GiB |
| Kích thước opening `τ` | 2.96 MiB | 4.83 MiB | 7.61 MiB |

Thời gian phát hành (KeyGen, User₁, Sign, User₂) là số chạy một luồng, trung bình
200 lần lặp trong mỗi lần chạy. Số ràng buộc và kích thước opening là tất định.

**So sánh với [BB26] trên cùng máy** (ML-DSA-44, cấu hình Bảng 4 của [BB26],
Rust 1.97, `bench/bb26/oneshot.rs`, thống kê bằng `bench/bb26/bb26_stats.awk`):

| [BB26] | Sign₁ | Prove | Verify | Proof |
|---|---|---|---|---|
| M2, 1 luồng | 241 ms | 897 ms | 545 ms | 1 011 909 B |
| M2, 4 luồng | 235 ms | 896 ms | 542 ms | 1 011 909 B |
| M2, chế độ Hashed, 1 luồng | ≈ 0 | 1167 ms | 558 ms | 1 037 509 B |
| Xeon, 1 luồng | 832 ms | 1102 ms | 998 ms | 1 011 909 B |
| Xeon, 2 luồng | 806 ms | 939 ms | 785 ms | 1 011 909 B |

### Các lần đo cũ (không dùng trong bản thảo)

* `bench/results/bench-2026-11-11.log`: Xeon, bản một luồng trước khi có OpenMP.
* `bench/results/bench-2026-11-11-apple.log`: máy ảo Linux aarch64 trên một máy
  Apple khác mà bản README trước ghi là "M4-series"; không tái lập được trên
  Mac mini M2 ở trên.
* `bench/results/bench-m2-2026-11-15.log`: máy ảo Linux aarch64 (4 vCPU, 3 GiB,
  GCC 11.4) trên chính Mac mini M2 ở trên; chậm hơn khoảng 2,4 lần so với chạy
  trực tiếp trên macOS.

## 6. Tham số an toàn (chi tiết ở `DESIGN.md` §3.3)

Mặc định λ của NIZK bằng λ của bộ ML-DSA (128/192/256): K = 2^14 ô mỗi hàng, mã
Reed–Solomon tốc độ 1/4 trên n = 2^16 cột, `t` = 428 / 641 / 855 cột mở, padding
`t_pad` = 512 / 768 / 1024, lặp s_I/s_L/s_Q = 3/2/2, 4/3/3, 6/4/4, digest và salt
Merkle 2λ bit. Khi đó `ε_rbr ≤ 2^−127.9 / 2^−191.9 / 2^−255.9`: đây là xác suất
thành công cho mỗi truy vấn Fiat–Shamir trong ROM cổ điển, không phải mức an toàn
theo danh mục NIST. Trong QROM các cận đã biết chỉ cho khoảng λ/2 bit; muốn nhắm
khoảng 128 bit trước kẻ tấn công lượng tử với ML-DSA-44 thì dùng
`mobs_set_ligero_params(lg_params_level(256))` (opening 6.48 MiB, chậm hơn 1.7–2.1 lần).
`lg_params_test()` chỉ dùng cho kiểm thử.

## 7. Ánh xạ với bản thảo (CSI, bản 23-11-2026 v2)

| Bản thảo | Mã nguồn |
|---|---|
| Lược đồ cơ sở `B[Sig,Com]`, Com = SHAKE256(DS_com‖r‖m) (Mục 3) | `mobs_user1`, `mobs_sign`, `mobs_user2` (`src/mobs.c`) |
| Mô-đun `M[B,NIZK]`: Open/Verify, nhãn = ctx (Mục 3) | `mobs_open`, `mobs_verify`, `stmt_digest` |
| Statement digest (Mục 4.3) | `stmt_digest`: "MOBS" ‖ ps ‖ n ‖ 0x00 ‖ pk ‖ (b_i ‖ y_i) |
| (O1) mở `m_D = y` (Mục 4.4) | `mldsa_circuit.c`, khối "(O1)" |
| (O2) cam kết, (O3) `μ`, (O7) `c̃` | Keccak circuit, khối "(O2)", "(O3)", "(O7)" |
| (O4) SampleInBall_B | `sampleinball_circuit` |
| (O5) `Az − c t₁ 2^d`, (O6) UseHint/Decompose | khối "(O5)+(O6)" |
| (O8) chuẩn của `z` (phân tích bit + kiểm tra cận trên), trọng số của `h` | khối "(O8a)", "(O8b)"; `bounded()` |
| Ligero/BCS, ZK và OSE (Mục 4.5, Phụ lục A) | `ligero.c`, `xof.c` (cSHAKE256) |

## 8. Giới hạn

* Không thời gian hằng ở phía tạo opening; cần chạy trên thiết bị tin cậy.
* Chưa có vị từ Φ(m) (ví dụ chứng minh tuổi ≥ 18 mà không mở năm sinh); gadget
  phân tích bit đã có sẵn để bổ sung.
* Mỗi thuộc tính 32 byte; tối đa 256 thuộc tính (`MOBS_MAX_ATTRS`).
* ZK và OSE của đúng biến thể Ligero/BCS này được chứng minh trong ROM cổ điển
  (Mệnh đề 7 và Phụ lục A của bản thảo). Chưa có chứng minh trong QROM
  (`DESIGN.md` §3.5).
* Mã của dự án dùng giấy phép MIT (xem `LICENSE`); `third_party/dilithium` giữ
  giấy phép gốc (CC0 hoặc Apache-2.0).
