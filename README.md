# MOBS[ML-DSA] — cài đặt tham chiếu bằng C

Cài đặt đầy đủ lược đồ **MOBS (Modular-Opening Blind Signatures)** theo bản thảo
`MOBS-main-06-11-2026-v2.tex`, với:

* **Người ký dùng ML-DSA (FIPS 204) nguyên bản**: ký mù 2 lượt, người ký chỉ nhận
  một chuỗi 32/48/64 byte `C = SHAKE256(DS_com‖r‖m)` và trả về đúng một chữ ký
  FIPS 204 trên `DS_iss‖C`. Không có thỏa thuận trước nào về vị trí sẽ mở.
* **Mô-đun mở (opening module)**: từ chữ ký cơ sở, người dùng mở **bất kỳ tập vị trí
  `D` nào** của `m`, bao nhiêu lần cũng được, gắn với ngữ cảnh `ctx`; các lần mở
  không liên kết được với nhau và với phiên ký.
* **NIZK: Ligero** (AHIV17) trên trường Goldilocks, biến thành không tương tác
  bằng biến đổi BCS/Fiat–Shamir với cSHAKE256 — chỉ dựa trên hàm băm, hậu lượng
  tử, không cần trusted setup. Quan hệ chứng minh là (O1)–(O8) của bản thảo.

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
simulation-extractability** (cho OMUF-MO), và — để giữ tính hậu lượng tử của
MOBS[ML-DSA] — không dựa trên giả thiết nào ngoài hàm băm và chính ML-DSA.

| Ứng viên | Hậu lượng tử / không setup | Trích xuất trực tuyến | Phù hợp với quan hệ (~85 % là Keccak) | Độ phức tạp cài đặt | Kích thước chứng minh |
|---|---|---|---|---|---|
| **Ligero + BCS** (chọn) | có / có (chỉ hash) | có, từ truy vấn Merkle (straight-line) | tốt: mạch R1CS tổng quát trên trường 64 bit | thấp: RS code + NTT + Merkle | lớn (vài MiB) |
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

Yêu cầu: GCC hoặc Clang 64-bit (cần `__int128`), `make`, `libm`. Đã kiểm thử trên
Ubuntu 24.04, GCC 13.3, x86-64. Trên Windows nên dùng WSL2 (MSVC không hỗ trợ
`__int128`).

```sh
make              # build cho ML-DSA-44/65/87 (mode 2/3/5)
make check        # kiểm thử chức năng (end-to-end dùng tham số Ligero nhỏ, KHÔNG an toàn)
make check-full   # end-to-end với tham số thật, ML-DSA-44 (~1 phút)
./build/test_mobs3 && ./build/test_mobs5   # tham số thật cho ML-DSA-65/87
./build/demo2     # ví dụ (thêm --fast để chạy nhanh với tham số thử)
./build/bench_mobs2 4 8 16 32 64           # benchmark theo n
```

Kết quả hiện tại: toàn bộ `make check` (110 kiểm tra) và các bài kiểm thử với
tham số thật cho cả ba mức đều qua; build với AddressSanitizer + UBSan sạch.

Các kiểm tra quan trọng: mạch SHAKE256 khớp `fips202.c`; SampleInBall trong mạch
khớp `poly_challenge`; chữ ký FIPS 204 thật thỏa mạch; giá trị mở sai, khóa công
khai sai, thuộc tính ẩn bị giả mạo, chữ ký hỏng → vi phạm ràng buộc; chứng minh bị
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

Kích thước thông điệp ký: `rho1` = 32/48/64 byte; `rho2` = 2420/3309/4627 byte
(chữ ký FIPS 204); `pk` = 1312/1952/2592 byte.

## 5. Kết quả đo

### 5.1. Đo lại ngày 11-11-2026 (số liệu dùng trong bản thảo `MOBS-main-11-11-2026-v1`)

Máy: 1 nhân Intel Xeon @ 2,10 GHz (máy ảo, ghim nhân bằng `taskset -c 0`), GCC 13.3
`-O2`, một luồng. Mỗi bộ tham số chạy 10 lần với n = 8, mở một nửa số vị trí
(`bench/run_bench_10.sh`); số liệu là trung bình ± độ lệch chuẩn (`bench/stats.py`).
Nhật ký gốc: `bench/results/bench-2026-11-11.log`.

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| KeyGen (ms) | 0,085 ± 0,007 | 0,165 ± 0,031 | 0,239 ± 0,005 |
| User₁ (ms) | 0,002 | 0,002 | 0,002 |
| Sign, FIPS 204 (ms) | 0,35 ± 0,03 | 0,63 ± 0,14 | 0,71 ± 0,04 |
| User₂ (ms) | 0,087 ± 0,002 | 0,154 ± 0,017 | 0,253 ± 0,008 |
| Open (s) | 13,06 ± 0,19 | 19,04 ± 0,22 | 30,84 ± 0,65 |
| Verify (s) | 7,62 ± 0,18 | 12,88 ± 0,21 | 21,95 ± 0,42 |
| kích thước opening `τ` | 2,96 MiB | 4,83 MiB | 7,61 MiB |

Độ lệch chuẩn tương đối của Open/Verify không quá 2,4 %. Số ràng buộc và kích thước
opening là tất định và trùng với lần đo trước.

### 5.2. Đo trên Apple M4 (11-11-2026)

Máy: 1 nhân của máy ảo Linux (aarch64, 4 vCPU) chạy trên Mac dùng chip Apple
M4-series, ghim nhân bằng `taskset -c 0`, GCC `-O2`. Cùng quy trình như 5.1;
nhật ký gốc: `bench/results/bench-2026-11-11-apple.log`.

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| KeyGen (ms) | 0,041 ± 0,001 | 0,079 ± 0,001 | 0,120 ± 0,009 |
| User₁ (ms) | 0,001 | 0,001 | 0,001 |
| Sign, FIPS 204 (ms) | 0,20 ± 0,02 | 0,31 ± 0,02 | 0,39 ± 0,02 |
| User₂ (ms) | 0,047 ± 0,001 | 0,075 ± 0,001 | 0,123 ± 0,002 |
| Open (s) | 7,15 ± 0,10 | 10,67 ± 0,06 | 17,15 ± 0,11 |
| Verify (s) | 4,08 ± 0,05 | 7,15 ± 0,04 | 12,34 ± 0,08 |

Độ lệch chuẩn tương đối của Open/Verify không quá 1,4 %. BB26 đo trên Apple M3 Pro
(macOS, Rust); vì vậy số liệu ở mục này là số nên dùng khi so sánh với BB26.

### 5.3. Lần đo trước (06-11-2026, một lần chạy cho mỗi cấu hình)

Máy: 1 nhân Intel Xeon @ 2,30 GHz (máy ảo), GCC 13.3 `-O2`, một luồng.

**Ký mù (ML-DSA-44, n = 8):** KeyGen 0,067 ms · User₁ 0,001 ms ·
Sign (FIPS 204) 0,26 ms · User₂ 0,072 ms.

**Mở/kiểm tra theo mức an toàn (n = 8, mở một nửa số vị trí):**

| | ML-DSA-44 (λ=128) | ML-DSA-65 (λ=192) | ML-DSA-87 (λ=256) |
|---|---|---|---|
| Keccak-f trong mạch | 12 | 13 | 16 |
| phép nhân / ràng buộc tuyến tính | 1,99 M / 0,58 M | 2,25 M / 0,64 M | 2,82 M / 0,79 M |
| kích thước opening `τ` | 2,96 MiB | 4,83 MiB | 7,61 MiB |
| Open (dựng mạch + chứng minh) | 0,3 + 9,7 s | 0,5 + 14,5 s | 0,6 + 23,6 s |
| Verify (dựng mạch + kiểm tra) | 0,4 + 5,5 s | 0,4 + 9,8 s | 0,5 + 16,6 s |
| bộ nhớ đỉnh | 0,76 GiB | 0,79 GiB | 1,04 GiB |

**Theo số thuộc tính n (ML-DSA-44, lần đo 06-11-2026):**

| n | Keccak-f | phép nhân | `τ` | Open | Verify |
|---|---|---|---|---|---|
| 4 | 11 | 1,84 M | 2,86 MiB | 9,6 s | 5,4 s |
| 8 | 12 | 1,99 M | 2,96 MiB | 10,0 s | 5,9 s |
| 16 | 14 | 2,29 M | 3,15 MiB | 11,7 s | 6,9 s |
| 32 | 17 | 2,73 M | 3,46 MiB | 14,4 s | 8,1 s |
| 64 | 25 | 3,92 M | 4,24 MiB | 19,8 s | 11,0 s |

Số Keccak-f khớp Bảng 2 của bản thảo. So sánh: GordieHowe chứng minh riêng phần chữ
ký ML-DSA-44 với 549 KiB; chữ ký mù trên ML-DSA nguyên bản của BB26 ≈ 1 MB. Bản này
lớn hơn 3–8 lần và chậm hơn do dùng Ligero thuần, một luồng, chưa tối ưu
(hướng cải thiện: song song hóa, Merkle multi-proof, lớp sumcheck cho Keccak).

## 6. Tham số an toàn (chi tiết ở `DESIGN.md` §3)

Mặc định mức λ của NIZK khớp mức NIST của ML-DSA: K = 2^14 ô mỗi hàng, tốc độ mã
1/4, `t` cột mở sao cho `(1 − e/n)^t ≤ 2^−λ` (t = 428 / 641 / 855), padding
ngẫu nhiên `t_pad ≥ t` (512 / 768 / 1024) cho ZK, lặp kiểm tra s_I/s_L/s_Q =
3/2/2, 4/3/3, 6/4/4; digest và salt Merkle 2λ bit (32/48/64 byte). Có thể đổi
bằng `mobs_set_ligero_params()`; `lg_params_test()` chỉ dùng cho kiểm thử.

## 7. Ánh xạ với bản thảo

| Bản thảo (v2) | Mã nguồn |
|---|---|
| Base scheme `B[Sig,Com]`, Com = SHAKE256(DS_com‖r‖m) | `mobs_user1`, `mobs_sign`, `mobs_user2` (`src/mobs.c`) |
| Module `M[B,NIZK]`: Open/Verify, nhãn = ctx | `mobs_open`, `mobs_verify`, `stmt_digest` |
| (O1) mở `m_D = y` | `mldsa_circuit.c`, khối "(O1)" |
| (O2) cam kết, (O3) `μ`, (O7) `c̃` | Keccak circuit, khối "(O2)", "(O3)", "(O7)" |
| (O4) SampleInBall_B | `sampleinball_circuit` |
| (O5) `Az − c t₁ 2^d`, (O6) UseHint/Decompose | khối "(O5)+(O6)" |
| (O8) chuẩn của `z`, trọng số của `h` | khối "(O8a)", "(O8b)" |
| NIZK có nhãn trong ROM, domain separation | `ligero.c`, `xof.c` (cSHAKE256) |

## 8. Giới hạn

* Không thời gian hằng ở phía tạo opening; cần chạy trên thiết bị tin cậy.
* Chưa có vị từ Φ(m) (ví dụ chứng minh tuổi ≥ 18 mà không mở năm sinh); gadget
  phân tích bit đã có sẵn để bổ sung.
* Mỗi thuộc tính 32 byte; tối đa 256 thuộc tính (`MOBS_MAX_ATTRS`).
* OSE của Ligero/BCS dựa trên lập luận trích xuất straight-line chuẩn trong ROM;
  chứng minh hình thức cho đúng biến thể này và trường hợp QROM còn mở
  (`DESIGN.md` §3.5).
* Mã của dự án dùng giấy phép MIT (xem `LICENSE`); `third_party/dilithium` giữ
  giấy phép gốc (CC0 hoặc Apache-2.0).
