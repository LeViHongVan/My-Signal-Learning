# CHƯƠNG 3: PHÂN TÍCH MÃ NGUỒN THƯ VIỆN LIBSIGNAL-PROTOCOL-C

---

## 3.1. Giới thiệu tổng quan về thư viện

### 3.1.1. Nguồn gốc và mục tiêu

Thư viện `libsignal-protocol-c` là hiện thực hóa bằng ngôn ngữ C của Giao thức Signal — một giao thức mật mã đầu cuối được phát triển bởi Open Whisper Systems (nay là Signal Foundation). Thư viện này cung cấp toàn bộ các thành phần mật mã học cần thiết để xây dựng hệ thống nhắn tin bảo mật, bao gồm trao đổi khóa X3DH (Extended Triple Diffie-Hellman), mã hóa Double Ratchet, quản lý phiên làm việc (session), nhắn tin nhóm, và xác minh danh tính. Mã nguồn được phát hành dưới giấy phép GPLv3 và được cấu trúc để có thể tích hợp vào nhiều nền tảng khác nhau như Linux, macOS, iOS, BlackBerry 10, và Windows.

Theo tệp `README.md`, thư viện "là một giao thức bảo mật tiến chuyển (ratcheting forward secrecy) hoạt động trong cả môi trường nhắn tin đồng bộ và bất đồng bộ". Đây là đặc tính cốt lõi giúp Signal Protocol trở thành tiêu chuẩn công nghiệp được ứng dụng trong WhatsApp, Facebook Messenger, Google Messages và nhiều ứng dụng khác.

### 3.1.2. Cấu trúc thư mục mã nguồn

Toàn bộ mã nguồn được tổ chức theo cấu trúc sau:

```
libsignal-protocol-c-master/
├── src/                        # Mã nguồn thư viện chính
│   ├── signal_protocol.h/c     # Module API cấp cao nhất và quản lý context
│   ├── signal_protocol_types.h # Định nghĩa kiểu dữ liệu toàn cục
│   ├── curve.h/c               # Mật mã khóa bất đối xứng Curve25519
│   ├── curve25519/             # Hiện thực toán học đường cong Curve25519
│   ├── hkdf.h/c                # Hàm dẫn xuất khóa HKDF (HMAC-based KDF)
│   ├── ratchet.h/c             # Cơ chế Double Ratchet cốt lõi
│   ├── key_helper.h/c          # Trợ giúp sinh khóa (Identity, PreKey, Signed PreKey)
│   ├── session_builder.h/c     # Xây dựng phiên làm việc qua X3DH
│   ├── session_cipher.h/c      # Mã hóa/giải mã tin nhắn qua Double Ratchet
│   ├── session_state.h/c       # Quản lý trạng thái phiên làm việc
│   ├── session_record.h/c      # Lưu trữ và tuần tự hóa bản ghi phiên
│   ├── session_pre_key.h/c     # Quản lý PreKey và SignedPreKey
│   ├── protocol.h/c            # Định nghĩa định dạng bản tin trên dây
│   ├── group_session_builder.h/c  # Xây dựng phiên nhắn tin nhóm
│   ├── group_cipher.h/c        # Mã hóa/giải mã nhắn tin nhóm
│   ├── sender_key.h/c          # Quản lý Sender Key
│   ├── fingerprint.h/c         # Sinh mã xác minh danh tính (Safety Number)
│   ├── device_consistency.h/c  # Đảm bảo nhất quán thiết bị đa thiết bị
│   └── protobuf-c/             # Thư viện Protocol Buffers cho C
├── tests/                      # Bộ kiểm thử đơn vị toàn diện
├── protobuf/                   # Định nghĩa schema protobuf
├── demo.c                      # Chương trình minh họa toàn bộ luồng X3DH + Double Ratchet
└── CMakeLists.txt              # Hệ thống build CMake
```

Cấu trúc này phản ánh kiến trúc phân lớp rõ ràng: lớp mật mã học nguyên thủy ở dưới cùng (Curve25519, HKDF), tiếp theo là lớp giao thức cốt lõi (ratchet, session), và cuối cùng là API cấp cao dành cho ứng dụng (signal_protocol).

---

## 3.2. Hệ thống kiểu dữ liệu và quản lý ngữ cảnh

### 3.2.1. Định nghĩa kiểu dữ liệu (`signal_protocol_types.h`)

Tệp `signal_protocol_types.h` là nền tảng của toàn bộ thư viện, định nghĩa tập hợp các kiểu dữ liệu trừu tượng được dùng xuyên suốt:

```c
/* Kiểu địa chỉ của một người nhận trong Signal Protocol */
typedef struct signal_protocol_address {
    const char *name;       /* Tên người dùng (số điện thoại) */
    size_t name_len;        /* Độ dài tên */
    int32_t device_id;      /* ID thiết bị vật lý */
} signal_protocol_address;

/* Hằng số kích thước khóa Ratchet */
#define RATCHET_CIPHER_KEY_LENGTH 32   /* Khóa mã hóa AES-256: 32 byte */
#define RATCHET_MAC_KEY_LENGTH    32   /* Khóa MAC HMAC-SHA256: 32 byte */
#define RATCHET_IV_LENGTH         16   /* Vector khởi tạo AES: 16 byte */

/* Cấu trúc chứa toàn bộ khóa của một tin nhắn */
typedef struct ratchet_message_keys {
    uint8_t cipher_key[RATCHET_CIPHER_KEY_LENGTH]; /* Khóa mã hóa */
    uint8_t mac_key[RATCHET_MAC_KEY_LENGTH];       /* Khóa xác thực */
    uint8_t iv[RATCHET_IV_LENGTH];                 /* Vectơ khởi tạo */
    uint32_t counter;                              /* Số đếm tin nhắn */
} ratchet_message_keys;
```

Điều đáng chú ý là tất cả kiểu phức tạp (như `ec_public_key`, `session_record`, `session_cipher`) chỉ được khai báo là các `typedef struct` mà không lộ cấu trúc nội bộ, thể hiện nguyên tắc đóng gói (encapsulation) chặt chẽ trong thư viện C này.

### 3.2.2. Hệ thống quản lý tham chiếu (`signal_protocol.h`)

Thư viện sử dụng cơ chế đếm tham chiếu (reference counting) thay cho quản lý bộ nhớ thủ công. Mỗi đối tượng trong thư viện đều kế thừa `signal_type_base` làm thành viên đầu tiên, và được quản lý thông qua hai macro:

```c
/* Tăng số đếm tham chiếu */
#define SIGNAL_REF(instance) signal_type_ref((signal_type_base *)instance)

/* Giảm số đếm tham chiếu; giải phóng bộ nhớ khi đếm về 0 */
#define SIGNAL_UNREF(instance) do { \
    signal_type_unref((signal_type_base *)instance); \
    instance = 0; \
} while(0)
```

Cơ chế này đảm bảo tính an toàn bộ nhớ khi nhiều module cùng chia sẻ các đối tượng mật mã học. Đặc biệt, dữ liệu nhạy cảm như khóa bí mật được xóa an toàn (zero-fill) trước khi giải phóng thông qua hàm `signal_explicit_bzero()`, nhằm ngăn chặn rò rỉ thông tin qua bộ nhớ.

### 3.2.3. Mã lỗi và ngữ cảnh toàn cục

Thư viện định nghĩa hệ thống mã lỗi nhất quán:

| Mã lỗi | Giá trị | Ý nghĩa |
|--------|---------|---------|
| `SG_SUCCESS` | 0 | Thành công |
| `SG_ERR_NOMEM` | -12 | Không đủ bộ nhớ |
| `SG_ERR_INVAL` | -22 | Đối số không hợp lệ |
| `SG_ERR_DUPLICATE_MESSAGE` | -1001 | Tin nhắn trùng lặp (tấn công replay) |
| `SG_ERR_INVALID_MAC` | -1004 | MAC không hợp lệ (tin nhắn bị giả mạo) |
| `SG_ERR_NO_SESSION` | -1008 | Chưa có phiên làm việc |
| `SG_ERR_UNTRUSTED_IDENTITY` | -1010 | Khóa định danh không đáng tin |
| `SG_ERR_INVALID_PROTO_BUF` | -1100 | Lỗi phân tích Protocol Buffer |

Ngữ cảnh toàn cục `signal_context` được khởi tạo thông qua `signal_context_create()` và là điểm tích hợp ba thành phần cốt lõi:
- **Nhà cung cấp mật mã học** (`signal_crypto_provider`): các hàm callback cho HMAC-SHA256, SHA-512, AES-CBC/CTR, và sinh số ngẫu nhiên.
- **Hàm khóa đồng bộ** (`lock`/`unlock`): bảo vệ trạng thái phiên trong môi trường đa luồng.
- **Hàm ghi log**: theo dõi hoạt động của thư viện.

---

## 3.3. Module mật mã học nền tảng

### 3.3.1. Mật mã đường cong Elliptic Curve25519 (`curve.h/.c`)

Module `curve.h` cung cấp toàn bộ các thao tác mật mã học trên đường cong Curve25519, bao gồm:

**Sinh và quản lý khóa:**
```c
/* Sinh cặp khóa Curve25519 ngẫu nhiên */
int curve_generate_key_pair(signal_context *context, ec_key_pair **key_pair);

/* Tạo khóa công khai từ khóa bí mật */
int curve_generate_public_key(ec_public_key **public_key, 
                               const ec_private_key *private_key);
```

**Trao đổi khóa Diffie-Hellman:**
```c
/* Tính thỏa thuận ECDH, trả về 32 byte bí mật chung */
int curve_calculate_agreement(uint8_t **shared_key_data, 
                               const ec_public_key *public_key, 
                               const ec_private_key *private_key);
```

Đây là hàm nền tảng được gọi nhiều lần trong quá trình X3DH. Kết quả là một chuỗi 32 byte biểu diễn bí mật chung Diffie-Hellman giữa hai bên.

**Chữ ký số (Schnorr trên Curve25519):**
```c
/* Ký dữ liệu, tạo chữ ký 64 byte */
int curve_calculate_signature(signal_context *context,
    signal_buffer **signature,
    const ec_private_key *signing_key,
    const uint8_t *message_data, size_t message_len);

/* Xác minh chữ ký */
int curve_verify_signature(const ec_public_key *signing_key,
    const uint8_t *message_data, size_t message_len,
    const uint8_t *signature_data, size_t signature_len);
```

Chữ ký Curve25519 có độ dài cố định **64 byte** (`CURVE_SIGNATURE_LEN`). Hàm xác minh trả về 1 nếu hợp lệ, 0 nếu không hợp lệ, và giá trị âm nếu có lỗi.

**Chữ ký VRF (Verifiable Random Function):**
```c
#define VRF_SIGNATURE_LEN 96  /* Chữ ký VRF dài 96 byte */

int curve_calculate_vrf_signature(signal_context *context,
    signal_buffer **signature,
    const ec_private_key *signing_key,
    const uint8_t *message_data, size_t message_len);

int curve_verify_vrf_signature(signal_context *context,
    signal_buffer **vrf_output,
    const ec_public_key *signing_key,
    const uint8_t *message_data, size_t message_len,
    const uint8_t *signature_data, size_t signature_len);
```

VRF được sử dụng trong module `device_consistency` để tạo ra đầu ra ngẫu nhiên có thể xác minh, giúp đảm bảo tính nhất quán giữa các thiết bị của một người dùng.

### 3.3.2. Hàm dẫn xuất khóa HKDF (`hkdf.h/.c`)

HKDF (HMAC-based Key Derivation Function, RFC 5869) là một trong những thành phần quan trọng nhất của giao thức Signal. Module `hkdf.c` thực thi hai giai đoạn theo đúng tiêu chuẩn:

**Giai đoạn Extract — tạo Pseudo-Random Key (PRK):**
```c
ssize_t hkdf_extract(hkdf_context *context,
    uint8_t **output,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *input_key_material, size_t input_key_material_len)
{
    /* Gọi HMAC-SHA256(salt, IKM) để tạo PRK */
    result = signal_hmac_sha256_init(context->global_context,
            &hmac_context, salt, salt_len);
    signal_hmac_sha256_update(context->global_context,
            hmac_context, input_key_material, input_key_material_len);
    signal_hmac_sha256_final(context->global_context,
            hmac_context, &mac_buffer);
    ...
}
```

**Giai đoạn Expand — mở rộng PRK thành khóa có độ dài tùy ý:**
```c
ssize_t hkdf_expand(hkdf_context *context,
    uint8_t **output,
    const uint8_t *prk, size_t prk_len,
    const uint8_t *info, size_t info_len,
    size_t output_len)
{
    int iterations = (int)ceil((double)output_len / (double)HASH_OUTPUT_SIZE);
    /* Lặp: T(i) = HMAC-SHA256(PRK, T(i-1) || info || i) */
    for(i = context->iteration_start_offset; 
        i < iterations + context->iteration_start_offset; i++) {
        signal_hmac_sha256_init(...);
        signal_hmac_sha256_update(... step_buffer ...);
        signal_hmac_sha256_update(... info ...);
        signal_hmac_sha256_update(... &i ...);
        signal_hmac_sha256_final(...);
    }
}
```

Thư viện hỗ trợ hai phiên bản giao thức (`message_version`):
- **Version 2**: `iteration_start_offset = 0` (vòng lặp bắt đầu từ 0).
- **Version 3** (hiện tại): `iteration_start_offset = 1` (vòng lặp bắt đầu từ 1, tuân thủ RFC 5869).

Hàm `hkdf_derive_secrets()` là điểm vào duy nhất cho bên ngoài, tích hợp cả Extract và Expand trong một lời gọi:

```c
ssize_t hkdf_derive_secrets(hkdf_context *context,
    uint8_t **output,
    const uint8_t *input_key_material, size_t input_key_material_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len,
    size_t output_len);
```

Hàm này được gọi ở nhiều nơi trong thư viện với các chuỗi `info` khác nhau để phân biệt ngữ cảnh sử dụng khóa:
- `"WhisperText"`: dẫn xuất Root Key và Chain Key ban đầu từ bí mật chung X3DH.
- `"WhisperRatchet"`: dẫn xuất Root Key và Chain Key mới trong mỗi bước Diffie-Hellman Ratchet.
- `"WhisperMessageKeys"`: dẫn xuất Message Keys (cipher_key, mac_key, IV) từ Chain Key.

---

## 3.4. Cơ chế trao đổi khóa X3DH (Extended Triple Diffie-Hellman)

### 3.4.1. Khởi tạo khóa và đăng ký (`key_helper.h/.c`)

Module `key_helper.h` cung cấp bộ hàm sinh khóa toàn diện, được gọi khi cài đặt ứng dụng lần đầu:

```c
/* Sinh cặp khóa định danh dài hạn — chỉ sinh MỘT LẦN khi cài đặt */
int signal_protocol_key_helper_generate_identity_key_pair(
    ratchet_identity_key_pair **key_pair, 
    signal_context *global_context);

/* Sinh ID đăng ký ngẫu nhiên từ 1-16380 */
int signal_protocol_key_helper_generate_registration_id(
    uint32_t *registration_id, int extended_range, 
    signal_context *global_context);

/* Sinh danh sách PreKey một lần dùng (One-Time PreKey) */
int signal_protocol_key_helper_generate_pre_keys(
    signal_protocol_key_helper_pre_key_list_node **head,
    unsigned int start, unsigned int count,
    signal_context *global_context);

/* Sinh Signed PreKey — ký bằng khóa định danh bí mật */
int signal_protocol_key_helper_generate_signed_pre_key(
    session_signed_pre_key **signed_pre_key,
    const ratchet_identity_key_pair *identity_key_pair,
    uint32_t signed_pre_key_id,
    uint64_t timestamp,
    signal_context *global_context);
```

Kết quả là bộ tham số sau cần được lưu trữ và đăng ký lên máy chủ:
- **Identity Key Pair (IK)**: Cặp khóa định danh bền vững (Curve25519).
- **Registration ID**: Số ngẫu nhiên định danh thiết bị.
- **PreKey Bundle**: Tập hợp One-Time PreKeys và Signed PreKey được công bố lên server.

### 3.4.2. Cấu trúc PreKey Bundle (`session_pre_key.h`)

Gói thông tin PreKey Bundle (hay còn gọi là Pre-Key Signal Message Bundle) được định nghĩa qua `session_pre_key_bundle_create()`:

```c
int session_pre_key_bundle_create(
    session_pre_key_bundle **bundle,
    uint32_t registration_id,       /* ID đăng ký của thiết bị */
    int device_id,                  /* ID thiết bị vật lý */
    uint32_t pre_key_id,            /* ID của One-Time PreKey */
    ec_public_key *pre_key_public,  /* Khóa công khai One-Time PreKey */
    uint32_t signed_pre_key_id,     /* ID của Signed PreKey */
    ec_public_key *signed_pre_key_public, /* Khóa công khai Signed PreKey */
    const uint8_t *signed_pre_key_signature_data, /* Chữ ký trên SPK */
    size_t signed_pre_key_signature_len,
    ec_public_key *identity_key);   /* Khóa định danh công khai */
```

Giới hạn ID của One-Time PreKey được định nghĩa là `PRE_KEY_MEDIUM_MAX_VALUE = 0xFFFFFF` (16.777.215), cho thấy thư viện hỗ trợ tối đa khoảng 16 triệu PreKey — quản lý trong cấu trúc vòng tròn (circular buffer).

### 3.4.3. Xây dựng phiên X3DH phía Alice (`session_builder.c`)

Hàm `session_builder_process_pre_key_bundle()` triển khai đầy đủ giao thức X3DH từ phía người khởi tạo:

**Bước 1 — Xác minh danh tính và chữ ký:**
```c
/* Kiểm tra xem khóa định danh của Bob có đáng tin không */
result = signal_protocol_identity_is_trusted_identity(
    builder->store, builder->remote_address,
    session_pre_key_bundle_get_identity_key(bundle));

/* Xác minh chữ ký của Signed PreKey bằng khóa định danh Bob */
result = curve_verify_signature(identity_key,
    signal_buffer_data(serialized_signed_pre_key),
    signal_buffer_len(serialized_signed_pre_key),
    signal_buffer_data(signature),
    signal_buffer_len(signature));
```

**Bước 2 — Sinh cặp khóa tạm thời (Ephemeral Key):**
```c
result = curve_generate_key_pair(builder->global_context, &our_base_key);
```

**Bước 3 — Cấu hình tham số Alice và gọi X3DH:**
```c
result = alice_signal_protocol_parameters_create(&parameters,
    our_identity_key,          /* IK_A: khóa định danh Alice */
    our_base_key,              /* EK_A: khóa tạm thời Alice */
    their_identity_key,        /* IK_B: khóa định danh Bob */
    their_signed_pre_key,      /* SPK_B: Signed PreKey của Bob */
    their_one_time_pre_key,    /* OPK_B: One-Time PreKey của Bob (tùy chọn) */
    their_signed_pre_key);     /* Ratchet Key ban đầu = SPK_B */

result = ratcheting_session_alice_initialize(
    state, parameters, builder->global_context);
```

### 3.4.4. Hiện thực X3DH phía Alice trong `ratchet.c`

Hàm `ratcheting_session_alice_initialize()` là trung tâm của toàn bộ cơ chế X3DH. Mã nguồn thực hiện tuần tự 4 phép tính ECDH để tạo ra bí mật chung:

```c
int ratcheting_session_alice_initialize(
    session_state *state,
    alice_signal_protocol_parameters *parameters,
    signal_context *global_context)
{
    /* Đệm dữ liệu liên tục (discontinuity) — 32 byte 0xFF */
    memset(discontinuity_data, 0xFF, sizeof(discontinuity_data));
    vpool_insert(&vp, ..., discontinuity_data, sizeof(discontinuity_data));

    /* DH1 = ECDH(IK_A_private, SPK_B_public) */
    curve_calculate_agreement(&agreement,
        parameters->their_signed_pre_key, 
        parameters->our_identity_key->private_key);
    vpool_insert(&vp, ..., agreement, agreement_len);

    /* DH2 = ECDH(EK_A_private, IK_B_public) */
    curve_calculate_agreement(&agreement,
        parameters->their_identity_key, 
        ec_key_pair_get_private(parameters->our_base_key));
    vpool_insert(&vp, ..., agreement, agreement_len);

    /* DH3 = ECDH(EK_A_private, SPK_B_public) */
    curve_calculate_agreement(&agreement,
        parameters->their_signed_pre_key, 
        ec_key_pair_get_private(parameters->our_base_key));
    vpool_insert(&vp, ..., agreement, agreement_len);

    /* DH4 = ECDH(EK_A_private, OPK_B_public) — chỉ khi có OPK */
    if(parameters->their_one_time_pre_key) {
        curve_calculate_agreement(&agreement,
            parameters->their_one_time_pre_key, 
            ec_key_pair_get_private(parameters->our_base_key));
        vpool_insert(&vp, ..., agreement, agreement_len);
    }

    /* Secret = F || DH1 || DH2 || DH3 || DH4 */
    secret = vpool_get_buf(&vp);
    secret_len = vpool_get_length(&vp);

    /* Dẫn xuất Root Key và Chain Key từ Secret bằng HKDF("WhisperText") */
    ratcheting_session_calculate_derived_keys(
        &derived_root, &derived_chain, secret, secret_len, global_context);

    /* Thực hiện bước DH Ratchet đầu tiên */
    ratchet_root_key_create_chain(derived_root,
        &sending_chain_root, &sending_chain_key,
        parameters->their_ratchet_key,
        ec_key_pair_get_private(sending_ratchet_key));
    ...
}
```

Trong đó `F` là chuỗi 32 byte `0xFF` — "discontinuity bytes" — nhằm đảm bảo đầu vào HKDF luôn có entropy tối thiểu ngay cả khi một số bí mật DH bằng 0.

### 3.4.5. Hiện thực X3DH phía Bob (`ratchet.c`)

Hàm `ratcheting_session_bob_initialize()` thực hiện 4 phép ECDH tương xứng theo thứ tự đảo ngược (tuân thủ tính giao hoán của ECDH):

```c
/* DH1' = ECDH(SPK_B_private, IK_A_public) ≡ DH1 */
curve_calculate_agreement(&agreement,
    parameters->their_identity_key, 
    ec_key_pair_get_private(parameters->our_signed_pre_key));

/* DH2' = ECDH(IK_B_private, EK_A_public) ≡ DH2 */
curve_calculate_agreement(&agreement,
    parameters->their_base_key, 
    parameters->our_identity_key->private_key);

/* DH3' = ECDH(SPK_B_private, EK_A_public) ≡ DH3 */
curve_calculate_agreement(&agreement,
    parameters->their_base_key, 
    ec_key_pair_get_private(parameters->our_signed_pre_key));

/* DH4' = ECDH(OPK_B_private, EK_A_public) ≡ DH4 */
if(parameters->our_one_time_pre_key) {
    curve_calculate_agreement(&agreement,
        parameters->their_base_key, 
        ec_key_pair_get_private(parameters->our_one_time_pre_key));
}
```

Sau đó Bob cũng gọi `ratcheting_session_calculate_derived_keys()` với cùng bí mật tổng hợp, thu được cùng Root Key và Chain Key như Alice — mà không cần giao tiếp thêm bất kỳ bước nào.

### 3.4.6. Dẫn xuất khóa phiên từ bí mật X3DH

```c
int ratcheting_session_calculate_derived_keys(
    ratchet_root_key **root_key, ratchet_chain_key **chain_key,
    uint8_t *secret, size_t secret_len, signal_context *global_context)
{
    static const char key_info[] = "WhisperText";
    hkdf_create(&kdf, 3, global_context);  /* Phiên bản 3 */
    memset(salt, 0, sizeof(salt));          /* Salt = 32 byte 0x00 */
    
    /* Dẫn xuất 64 byte: 32 byte Root Key + 32 byte Chain Key */
    hkdf_derive_secrets(kdf, &output,
        secret, secret_len,
        salt, sizeof(salt),
        (uint8_t *)key_info, sizeof(key_info) - 1, 64);

    ratchet_root_key_create(&root_key_result, kdf, output, 32, ...);
    ratchet_chain_key_create(&chain_key_result, kdf, output + 32, 32, 0, ...);
}
```

Kết quả là:
- **Root Key (RK)**: 32 byte đầu tiên — là "hạt giống" để mở rộng cây khóa.
- **Chain Key (CK)**: 32 byte tiếp theo — là cơ sở để sinh Message Keys.

---

## 3.5. Cơ chế Double Ratchet

### 3.5.1. Cấu trúc khóa chuỗi và khóa gốc (`ratchet.c`)

**Ratchet Root Key** lưu trữ trạng thái của "ratchet Diffie-Hellman":
```c
struct ratchet_root_key {
    signal_type_base base;        /* Header đếm tham chiếu */
    signal_context *global_context;
    hkdf_context *kdf;            /* Ngữ cảnh HKDF */
    uint8_t *key;                 /* Dữ liệu khóa gốc */
    size_t key_len;               /* Độ dài (thường 32 byte) */
};
```

**Ratchet Chain Key** lưu trữ trạng thái của "ratchet đối xứng":
```c
struct ratchet_chain_key {
    signal_type_base base;
    signal_context *global_context;
    hkdf_context *kdf;
    uint8_t *key;                 /* Dữ liệu khóa chuỗi */
    size_t key_len;               /* Thường 32 byte */
    uint32_t index;               /* Số đếm tin nhắn hiện tại */
};
```

### 3.5.2. Vòng xoay DH Ratchet (`ratchet_root_key_create_chain`)

Mỗi lần một trong hai bên gửi tin nhắn sau khi nhận được khóa ephemeral mới của đối phương, vòng xoay DH Ratchet được kích hoạt:

```c
int ratchet_root_key_create_chain(
    ratchet_root_key *root_key,
    ratchet_root_key **new_root_key, 
    ratchet_chain_key **new_chain_key,
    ec_public_key *their_ratchet_key,
    ec_private_key *our_ratchet_key_private)
{
    static const char key_info[] = "WhisperRatchet";
    
    /* Tính ECDH với cặp khóa Ratchet mới */
    curve_calculate_agreement(&shared_secret, 
        their_ratchet_key, our_ratchet_key_private);
    
    /* HKDF(Root_Key, DH_output, "WhisperRatchet") → 64 byte */
    hkdf_derive_secrets(root_key->kdf, &derived_secret,
        shared_secret, shared_secret_len,
        root_key->key, root_key->key_len,   /* Salt = Root Key hiện tại */
        (uint8_t *)key_info, sizeof(key_info) - 1,
        DERIVED_ROOT_SECRETS_SIZE /* = 64 */);

    /* 32 byte đầu → Root Key mới */
    ratchet_root_key_create(&new_root_key_result, ..., derived_secret, 32, ...);
    /* 32 byte sau → Chain Key mới (index = 0) */
    ratchet_chain_key_create(&new_chain_key_result, ..., derived_secret + 32, 32, 0, ...);
}
```

Cơ chế này đảm bảo **Forward Secrecy (Bảo mật tiến)**: mỗi vòng xoay tạo ra Chain Key hoàn toàn mới, và khi Root Key cũ bị xóa, không thể tính ngược lại các Chain Key trước đó.

### 3.5.3. Vòng xoay đối xứng KDF Chain — Sinh Message Keys

Mỗi khi cần mã hóa/giải mã một tin nhắn, Chain Key được tiến lên một bước để sinh Message Keys:

```c
int ratchet_chain_key_get_message_keys(
    ratchet_chain_key *chain_key, 
    ratchet_message_keys *message_keys)
{
    static const uint8_t message_key_seed = 0x01;
    static const char key_material_seed[] = "WhisperMessageKeys";
    
    /* Bước 1: HMAC-SHA256(Chain_Key, 0x01) → Input Key Material */
    ratchet_chain_key_get_base_material(chain_key, &input_key_material,
        &message_key_seed, sizeof(message_key_seed));

    /* Bước 2: HKDF(IKM, salt=0x00, "WhisperMessageKeys") → 80 byte */
    hkdf_derive_secrets(chain_key->kdf,
        &key_material_data,
        input_key_material, input_key_material_len,
        salt /* 32 byte 0x00 */, sizeof(salt),
        (uint8_t *)key_material_seed, sizeof(key_material_seed) - 1,
        DERIVED_MESSAGE_SECRETS_SIZE /* = 80 */);

    /* Phân phối 80 byte → cipher_key (32) + mac_key (32) + iv (16) */
    memcpy(message_keys->cipher_key, key_material_data, 
           RATCHET_CIPHER_KEY_LENGTH);       /* 32 byte */
    memcpy(message_keys->mac_key, 
           key_material_data + RATCHET_CIPHER_KEY_LENGTH, 
           RATCHET_MAC_KEY_LENGTH);           /* 32 byte */
    memcpy(message_keys->iv, 
           key_material_data + RATCHET_CIPHER_KEY_LENGTH + RATCHET_MAC_KEY_LENGTH, 
           RATCHET_IV_LENGTH);               /* 16 byte */
    message_keys->counter = chain_key->index;
}
```

Kế tiếp, Chain Key được tiến lên một bước để đảm bảo Break-in Recovery:

```c
int ratchet_chain_key_create_next(
    const ratchet_chain_key *chain_key, 
    ratchet_chain_key **next_chain_key)
{
    static const uint8_t chain_key_seed = 0x02;
    
    /* HMAC-SHA256(Chain_Key, 0x02) → Chain Key tiếp theo */
    ratchet_chain_key_get_base_material(chain_key, &next_key,
        &chain_key_seed, sizeof(chain_key_seed));
    
    /* Tạo Chain Key mới với index tăng thêm 1 */
    ratchet_chain_key_create(next_chain_key, ..., next_key, next_key_len,
        chain_key->index + 1, ...);
}
```

Tóm lại, quy trình đối xứng KDF Ratchet sử dụng hai seed khác nhau:
- **Seed = 0x01**: Để dẫn xuất Message Keys (dùng để mã hóa tin nhắn).
- **Seed = 0x02**: Để tạo Chain Key tiếp theo (tiến ratchet lên).

Điều quan trọng là sau khi Message Keys được tạo ra, Chain Key cũ cần bị xóa; Message Keys cũng cần bị xóa sau khi sử dụng. Điều này đảm bảo rằng nếu một Chain Key bị lộ, chỉ các tin nhắn từ thời điểm đó trở đi mới bị ảnh hưởng.

---

## 3.6. Module quản lý phiên làm việc

### 3.6.1. Trạng thái phiên (`session_state.h/.c`)

`session_state` là cấu trúc lưu trữ toàn bộ trạng thái mật mã học tại một thời điểm của phiên làm việc, bao gồm:
- Root Key hiện tại.
- Sender Chain Key (Chain Key đang dùng để gửi).
- Danh sách Receiver Chain (cho phép giải mã tin nhắn đến từ nhiều vòng DH Ratchet khác nhau).
- Khóa định danh cục bộ và từ xa.
- Danh sách Message Keys còn chờ xử lý (skipped message keys).
- Phiên bản giao thức và các thông tin đăng ký.

### 3.6.2. Bản ghi phiên (`session_record.h/.c`)

`session_record` đóng gói một `session_state` hiện tại cùng với danh sách các trạng thái phiên đã lưu trữ (previous session states). Cơ chế này cho phép:
- Lưu trữ phiên cũ khi phiên mới được thiết lập.
- Thử giải mã trên tất cả các phiên nếu phiên hiện tại thất bại.

```c
/* Nếu phiên làm việc đã có, lưu trữ trạng thái cũ trước khi tạo mới */
if(!session_record_is_fresh(record)) {
    result = session_record_archive_current_state(record);
}
```

Khi giải mã thất bại trên phiên hiện tại, hệ thống tự động thử các phiên cũ:
```c
previous_states_node = session_record_get_previous_states_head(record);
while(previous_states_node) {
    result = session_cipher_decrypt_from_state_and_signal_message(
        cipher, state_copy, ciphertext, &result_buf);
    if(result >= SG_SUCCESS) {
        session_record_promote_state(record, state_copy);
        break;
    }
    ...
}
```

### 3.6.3. Giao diện lưu trữ theo callback pattern (`signal_protocol.h`)

Thư viện sử dụng mô hình callback để tách biệt hoàn toàn logic giao thức với cơ chế lưu trữ. Có 5 giao diện lưu trữ cần được hiện thực:

**1. Session Store** — lưu trữ trạng thái phiên:
```c
typedef struct signal_protocol_session_store {
    /* Nạp phiên theo địa chỉ (tên + device_id) */
    int (*load_session_func)(signal_buffer **record, signal_buffer **user_record,
        const signal_protocol_address *address, void *user_data);

    /* Lấy danh sách thiết bị đang có phiên với một người nhận */
    int (*get_sub_device_sessions_func)(signal_int_list **sessions,
        const char *name, size_t name_len, void *user_data);

    /* Lưu phiên sau khi cập nhật */
    int (*store_session_func)(const signal_protocol_address *address,
        uint8_t *record, size_t record_len, ...);

    /* Kiểm tra sự tồn tại của phiên */
    int (*contains_session_func)(...);

    /* Xóa phiên */
    int (*delete_session_func)(...);

    /* Xóa toàn bộ phiên của một người nhận */
    int (*delete_all_sessions_func)(...);

    void (*destroy_func)(void *user_data);
    void *user_data;  /* Con trỏ dữ liệu ứng dụng */
} signal_protocol_session_store;
```

**2. PreKey Store** — quản lý One-Time PreKeys:
```c
typedef struct signal_protocol_pre_key_store {
    int (*load_pre_key)(signal_buffer **record, uint32_t pre_key_id, ...);
    int (*store_pre_key)(uint32_t pre_key_id, uint8_t *record, size_t record_len, ...);
    int (*contains_pre_key)(uint32_t pre_key_id, ...);
    int (*remove_pre_key)(uint32_t pre_key_id, ...);   /* Xóa sau khi dùng một lần */
    ...
} signal_protocol_pre_key_store;
```

**3. Signed PreKey Store** — quản lý Signed PreKeys.

**4. Identity Key Store** — quản lý khóa định danh và tin tưởng:
```c
typedef struct signal_protocol_identity_key_store {
    /* Lấy cặp khóa định danh cục bộ */
    int (*get_identity_key_pair)(signal_buffer **public_data, 
        signal_buffer **private_data, ...);

    /* Lấy Registration ID cục bộ */
    int (*get_local_registration_id)(void *user_data, uint32_t *registration_id);

    /* Lưu khóa định danh của người dùng từ xa */
    int (*save_identity)(...);

    /* Kiểm tra xem khóa định danh có đáng tin không — TOFU model */
    int (*is_trusted_identity)(...);
    ...
} signal_protocol_identity_key_store;
```

**5. Sender Key Store** — quản lý khóa người gửi cho nhắn tin nhóm.

Trong file `demo.c`, toàn bộ 5 cửa hàng này được hiện thực sử dụng bộ nhớ trong (in-memory hash table thông qua thư viện `uthash`), minh họa cách tích hợp thư viện trong thực tế.

---

## 3.7. Module mã hóa/giải mã tin nhắn (`session_cipher.h/.c`)

### 3.7.1. Cấu trúc Session Cipher

`session_cipher` là điểm vào chính cho tất cả các thao tác mã hóa và giải mã:
```c
struct session_cipher {
    signal_protocol_store_context *store;         /* Ngữ cảnh lưu trữ */
    const signal_protocol_address *remote_address; /* Địa chỉ đối phương */
    session_builder *builder;                       /* Builder để xử lý X3DH */
    signal_context *global_context;
    int (*decrypt_callback)(...);  /* Callback sau khi giải mã thành công */
    int inside_callback;           /* Ngăn chặn gọi lại đệ quy */
    void *user_data;
};
```

### 3.7.2. Mã hóa tin nhắn (`session_cipher_encrypt`)

Luồng xử lý mã hóa tuân thủ đầy đủ giao thức Double Ratchet:

1. **Nạp trạng thái phiên** từ session store.
2. **Lấy Sender Chain Key** từ trạng thái phiên hiện tại.
3. **Sinh Message Keys** từ Chain Key: `cipher_key (32 byte) + mac_key (32 byte) + iv (16 byte)`.
4. **Mã hóa bằng AES-CBC**: dùng `cipher_key` và `iv` để mã hóa plaintext.
5. **Tạo Signal Message**: đóng gói ciphertext cùng với Sender Ratchet Key, counter, previous counter.
6. **Tính MAC**: HMAC-SHA256 trên toàn bộ nội dung tin nhắn dùng `mac_key`.
7. **Kiểm tra Unacknowledged PreKey**: nếu phiên chưa được xác nhận, đóng gói thêm thông tin X3DH vào `pre_key_signal_message`.
8. **Tiến Chain Key** lên bước tiếp theo và lưu lại.

```c
result = signal_message_create(&message,
    session_version,
    message_keys.mac_key, sizeof(message_keys.mac_key),
    sender_ephemeral,         /* Khóa Ratchet gửi hiện tại */
    chain_key_index,          /* Số đếm tin nhắn */
    previous_counter,
    ciphertext_data, ciphertext_len,
    local_identity_key, remote_identity_key,
    cipher->global_context);
```

### 3.7.3. Giải mã tin nhắn PreKey (`session_cipher_decrypt_pre_key_signal_message`)

Luồng giải mã tin nhắn PreKey (tin nhắn đầu tiên trong phiên mới):

1. **Nạp session record** từ store.
2. **Xử lý X3DH phía Bob** qua `session_builder_process_pre_key_signal_message()`:
   - Xác minh khóa định danh của người gửi.
   - Tính 4 phép ECDH theo thứ tự của Bob.
   - Khởi tạo trạng thái phiên mới.
3. **Giải mã tin nhắn** thực tế bằng `session_cipher_decrypt_from_record_and_signal_message()`.
4. **Gọi callback** sau khi giải mã thành công (cho phép ứng dụng lưu plaintext trước khi commit trạng thái).
5. **Lưu trạng thái phiên** đã cập nhật.
6. **Xóa One-Time PreKey** đã dùng (`signal_protocol_pre_key_remove_key()`).

### 3.7.4. Giải mã qua các trạng thái phiên

Khi giải mã một `signal_message` thông thường, hệ thống thực hiện theo cơ chế "thử-và-leo-trèo":

```c
/* Thử với trạng thái phiên hiện tại */
result = session_cipher_decrypt_from_state_and_signal_message(
    cipher, state_copy, ciphertext, &result_buf);
if(result >= SG_SUCCESS) {
    session_record_set_state(record, state_copy);
    goto complete;
}

/* Nếu thất bại, thử các trạng thái phiên đã lưu */
while(previous_states_node) {
    result = session_cipher_decrypt_from_state_and_signal_message(...);
    if(result >= SG_SUCCESS) {
        /* Đưa phiên thành công lên đầu */
        session_record_promote_state(record, state_copy);
        break;
    }
}
```

Bên trong `session_cipher_decrypt_from_state_and_signal_message()`, luồng xử lý bao gồm:
1. Lấy khóa Ratchet của người gửi từ tin nhắn: `their_ephemeral`.
2. Gọi `session_cipher_get_or_create_chain_key()`: nếu khóa Ratchet mới, thực hiện vòng xoay DH Ratchet để tạo Chain Key mới.
3. Gọi `session_cipher_get_or_create_message_keys()`: lấy Message Keys theo số thứ tự (counter), hỗ trợ tin nhắn đến ngoài thứ tự.
4. Xác minh MAC trước khi giải mã.
5. Giải mã bằng AES-CBC dùng `cipher_key` và `iv`.

---

## 3.8. Định dạng bản tin trên đường truyền (`protocol.h/.c`)

### 3.8.1. Các loại bản tin

Thư viện định nghĩa 4 loại bản tin với mã định danh riêng:

| Loại | Giá trị | Mô tả |
|------|---------|-------|
| `CIPHERTEXT_SIGNAL_TYPE` | 2 | Signal Message — tin nhắn thông thường trong phiên đã thiết lập |
| `CIPHERTEXT_PREKEY_TYPE` | 3 | Pre-Key Signal Message — tin nhắn đầu tiên, kèm X3DH handshake |
| `CIPHERTEXT_SENDERKEY_TYPE` | 4 | Sender Key Message — tin nhắn nhóm |
| `CIPHERTEXT_SENDERKEY_DISTRIBUTION_TYPE` | 5 | Sender Key Distribution — phân phối khóa nhóm |

Phiên bản giao thức hiện tại là `CIPHERTEXT_CURRENT_VERSION = 3`.

### 3.8.2. Signal Message

`signal_message_create()` tạo một bản tin Signal với cấu trúc:
- **Phiên bản** và **loại** bản tin.
- **Khóa Ratchet của người gửi** (công khai): cho phép người nhận thực hiện vòng xoay DH Ratchet.
- **Counter** và **Previous Counter**: số đếm tin nhắn, hỗ trợ xử lý tin nhắn ngoài thứ tự.
- **Ciphertext body**: nội dung đã mã hóa AES-CBC.
- **MAC**: HMAC-SHA256 trên toàn bộ nội dung, tính bằng `mac_key` riêng của từng tin nhắn.

### 3.8.3. Pre-Key Signal Message

Đây là loại bản tin đặc biệt gửi trong lần đầu thiết lập phiên, chứa thêm:
- **Registration ID**: định danh thiết bị gửi.
- **Pre-Key ID**: ID của One-Time PreKey được sử dụng.
- **Signed Pre-Key ID**: ID của Signed PreKey được sử dụng.
- **Base Key**: Khóa tạm thời công khai của người gửi (EK_A).
- **Identity Key**: Khóa định danh công khai của người gửi (IK_A).
- **Signal Message** đã mã hóa: đính kèm bên trong.

### 3.8.4. Tuần tự hóa bằng Protocol Buffers

Tất cả bản tin được tuần tự hóa sử dụng Protocol Buffers (protobuf-c). Các schema được định nghĩa trong thư mục `protobuf/` và được biên dịch thành mã C trong `src/WhisperTextProtocol.pb-c.h/.c` và `src/LocalStorageProtocol.pb-c.h/.c`. Điều này đảm bảo tính tương thích nhị phân giữa các nền tảng khác nhau.

---

## 3.9. Nhắn tin nhóm

### 3.9.1. Mô hình Sender Key

Signal Protocol sử dụng cơ chế "Sender Key" cho nhắn tin nhóm, khác với phương pháp mã hóa cho từng thành viên:

- Mỗi thành viên nhóm sinh một cặp khóa đường cong (`sender_signing_key`) và một khóa đối xứng (`sender_key`) riêng.
- Thành viên gửi phân phối khóa này đến từng thành viên khác thông qua kênh đã mã hóa end-to-end cá nhân (Signal Message thông thường).
- Tin nhắn nhóm được mã hóa một lần bằng Sender Key, giúp giảm thiểu chi phí tính toán so với mã hóa N lần.

### 3.9.2. Group Session Builder (`group_session_builder.h`)

```c
/* Tạo phiên nhóm và sinh Sender Key Distribution Message */
int group_session_builder_create_session(
    group_session_builder *builder,
    sender_key_distribution_message **distribution_message,
    const signal_protocol_sender_key_name *sender_key_name);

/* Xử lý Sender Key Distribution nhận được — thiết lập phiên nhận */
int group_session_builder_process_session(
    group_session_builder *builder,
    const signal_protocol_sender_key_name *sender_key_name,
    sender_key_distribution_message *distribution_message);
```

Phiên nhóm là đơn hướng: phiên gửi và phiên nhận được tách biệt hoàn toàn. Khóa trong nhóm được định danh theo bộ ba `(group_id, sender_id, device_id)`.

### 3.9.3. Group Cipher (`group_cipher.h`)

```c
/* Mã hóa tin nhắn nhóm */
int group_cipher_encrypt(group_cipher *cipher,
    const uint8_t *padded_plaintext, size_t padded_plaintext_len,
    ciphertext_message **encrypted_message);

/* Giải mã Sender Key Message */
int group_cipher_decrypt(group_cipher *cipher,
    sender_key_message *ciphertext, void *decrypt_context,
    signal_buffer **plaintext);
```

`sender_key_message` bao gồm:
- **Key ID**: định danh Sender Key đang được dùng.
- **Iteration**: số đếm để thực hiện KDF Ratchet (tương tự Chain Key ratchet nhưng chỉ đối xứng, không có DH).
- **Ciphertext**: nội dung đã mã hóa AES-CBC.
- **Chữ ký**: chữ ký Curve25519 trên toàn bộ bản tin, xác minh danh tính người gửi.

---

## 3.10. Xác minh danh tính (`fingerprint.h/.c`)

### 3.10.1. Safety Number (Mã an toàn)

Thư viện cung cấp cơ chế tạo "Safety Number" (hay Fingerprint) để hai người dùng có thể xác minh ngoài băng tần (out-of-band) rằng họ thực sự đang giao tiếp với nhau và không bị tấn công Man-in-the-Middle:

```c
int fingerprint_generator_create(
    fingerprint_generator **generator,
    int iterations,           /* Số vòng lặp: 1024 ≈ 109.7 bit; 5200 > 112 bit */
    int scannable_version,    /* Phiên bản định dạng QR code: 0 hoặc 1 */
    signal_context *global_context);

int fingerprint_generator_create_for(
    fingerprint_generator *generator,
    const char *local_stable_identifier,      /* Số điện thoại cục bộ */
    const ec_public_key *local_identity_key,  /* Khóa định danh cục bộ */
    const char *remote_stable_identifier,     /* Số điện thoại đối phương */
    const ec_public_key *remote_identity_key, /* Khóa định danh đối phương */
    fingerprint **fingerprint_val);
```

### 3.10.2. Hai dạng fingerprint

Kết quả tạo ra hai dạng fingerprint:
- **Displayable Fingerprint**: chuỗi 60 chữ số thập phân, chia làm 12 nhóm 5 chữ số. Người dùng đọc và so sánh qua điện thoại hoặc gặp mặt trực tiếp.
- **Scannable Fingerprint**: định dạng nhị phân có thể mã hóa thành QR code để quét và so sánh tự động.

```c
/* So sánh fingerprint QR code */
int scannable_fingerprint_compare(
    const scannable_fingerprint *scannable,
    const scannable_fingerprint *other_scannable);
/* Trả về 1 nếu khớp, 0 nếu không khớp */
/* SG_ERR_FP_VERSION_MISMATCH nếu khác phiên bản */
/* SG_ERR_FP_IDENT_MISMATCH nếu số điện thoại không khớp */
```

---

## 3.11. Nhất quán thiết bị đa thiết bị (`device_consistency.h/.c`)

Trong môi trường đa thiết bị, cần đảm bảo rằng tất cả thiết bị của một người dùng đều "nhìn thấy" cùng tập hợp khóa định danh. Module `device_consistency` giải quyết vấn đề này bằng giao thức dựa trên VRF:

```c
/* Tạo commitment từ danh sách khóa định danh của tất cả thiết bị */
int device_consistency_commitment_create(
    device_consistency_commitment **commitment,
    uint32_t generation,
    ec_public_key_list *identity_key_list,
    signal_context *global_context);

/* Sinh Device Consistency Message để gửi đến các thiết bị khác */
int device_consistency_message_create_from_pair(
    device_consistency_message **message,
    device_consistency_commitment *commitment,
    ec_key_pair *identity_key_pair,
    signal_context *global_context);

/* Sinh mã nhất quán có thể hiển thị — so sánh giữa các thiết bị */
int device_consistency_code_generate_for(
    device_consistency_commitment *commitment,
    device_consistency_signature_list *signatures,
    char **code_string,
    signal_context *global_context);
```

---

## 3.12. Nhà cung cấp mật mã học (`signal_crypto_provider`)

Một điểm thiết kế nổi bật của thư viện là **không tích hợp cố định** bất kỳ thư viện mật mã học nào. Thay vào đó, ứng dụng phải cung cấp các hàm mật mã thông qua cấu trúc callback:

```c
typedef struct signal_crypto_provider {
    /* Sinh số ngẫu nhiên an toàn */
    int (*random_func)(uint8_t *data, size_t len, void *user_data);

    /* HMAC-SHA256: Init → Update → Final → Cleanup */
    int (*hmac_sha256_init_func)(...);
    int (*hmac_sha256_update_func)(...);
    int (*hmac_sha256_final_func)(...);
    void (*hmac_sha256_cleanup_func)(...);

    /* SHA-512: Init → Update → Final → Cleanup */
    int (*sha512_digest_init_func)(...);
    int (*sha512_digest_update_func)(...);
    int (*sha512_digest_final_func)(...);
    void (*sha512_digest_cleanup_func)(...);

    /* AES (hỗ trợ AES-CTR và AES-CBC) */
    int (*encrypt_func)(signal_buffer **output, int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len, ...);
    int (*decrypt_func)(...);

    void *user_data;
} signal_crypto_provider;
```

Hằng số định danh chế độ mã hóa:
- `SG_CIPHER_AES_CTR_NOPADDING = 1`: AES chế độ Counter (CTR), không đệm.
- `SG_CIPHER_AES_CBC_PKCS5 = 2`: AES chế độ Cipher Block Chaining (CBC) với đệm PKCS#5.

Trong file `demo.c`, nhà cung cấp mật mã học được hiện thực sử dụng Windows BCrypt API — minh họa sự linh hoạt trong tích hợp trên nền tảng Windows:

```c
static void setup_bcrypt_crypto_provider(signal_context *context) {
    signal_crypto_provider provider = {
        .random_func          = bcrypt_random_generator,
        .hmac_sha256_init_func = bcrypt_hmac_sha256_init,
        .hmac_sha256_update_func = bcrypt_hmac_sha256_update,
        .hmac_sha256_final_func = bcrypt_hmac_sha256_final,
        .hmac_sha256_cleanup_func = bcrypt_hmac_sha256_cleanup,
        .sha512_digest_init_func = bcrypt_sha512_digest_init,
        .sha512_digest_update_func = bcrypt_sha512_digest_update,
        .sha512_digest_final_func = bcrypt_sha512_digest_final,
        .sha512_digest_cleanup_func = bcrypt_sha512_digest_cleanup,
        .encrypt_func = bcrypt_encrypt,
        .decrypt_func = bcrypt_decrypt,
        .user_data = NULL
    };
    signal_context_set_crypto_provider(context, &provider);
}
```

---

## 3.13. Bộ kiểm thử đơn vị

Thư mục `tests/` chứa 17 tệp kiểm thử toàn diện, bao phủ mọi thành phần của thư viện:

| Tệp kiểm thử | Nội dung kiểm thử |
|---|---|
| `test_curve25519.c` (17 KB) | Các thao tác mật mã Curve25519: sinh khóa, ECDH, ký/xác minh |
| `test_hkdf.c` (6.8 KB) | Hàm dẫn xuất khóa HKDF với các vector kiểm thử |
| `test_ratchet.c` (26 KB) | Cơ chế Double Ratchet: khởi tạo, vòng xoay, sinh khóa |
| `test_session_builder.c` (65 KB) | Xây dựng phiên qua X3DH với nhiều kịch bản |
| `test_session_cipher.c` (18 KB) | Mã hóa và giải mã tin nhắn |
| `test_session_record.c` (26 KB) | Tuần tự hóa và phục hồi bản ghi phiên |
| `test_simultaneous_initiate.c` (75 KB) | Kịch bản cả hai bên đồng thời khởi tạo phiên |
| `test_group_cipher.c` (33 KB) | Nhắn tin nhóm với nhiều thành viên |
| `test_key_helper.c` (10 KB) | Sinh và quản lý các loại khóa |
| `test_fingerprint.c` (22 KB) | Sinh và xác minh Safety Number |
| `test_protocol.c` (12 KB) | Tuần tự hóa/giải tuần tự hóa các loại bản tin |
| `test_sender_key_record.c` (12 KB) | Quản lý Sender Key Record |
| `test_device_consistency.c` (9.8 KB) | Nhất quán thiết bị đa thiết bị |

---

## 3.14. Luồng hoạt động tổng thể — Minh họa qua `demo.c`

File `demo.c` trong thư viện là ví dụ hoàn chỉnh nhất về cách tích hợp và sử dụng toàn bộ thư viện. Chương trình mô phỏng cuộc hội thoại bảo mật đầu cuối giữa Alice và Bob theo 6 bước:

**Bước 1 — Khởi tạo ngữ cảnh và nhà cung cấp mật mã:**
```c
signal_context_create(&global_context, NULL);
signal_context_set_log_function(global_context, log_cb);
setup_bcrypt_crypto_provider(global_context);
```

**Bước 2 — Khởi tạo cửa hàng lưu trữ cho Alice và Bob:**
```c
signal_protocol_store_context_create(&alice_store, global_context);
signal_protocol_store_context_set_session_store(alice_store, &session_store);
signal_protocol_store_context_set_pre_key_store(alice_store, &pre_key_store);
signal_protocol_store_context_set_signed_pre_key_store(alice_store, &signed_pre_key_store);
signal_protocol_store_context_set_identity_key_store(alice_store, &identity_store);
```

**Bước 3 — Bob sinh và đăng ký PreKey Bundle:**
```c
signal_protocol_key_helper_generate_identity_key_pair(&bob_identity_key, context);
signal_protocol_key_helper_generate_pre_keys(&bob_pre_keys, 1, 1, context);
signal_protocol_key_helper_generate_signed_pre_key(&bob_signed_pre_key, 
    bob_identity_key, 1, timestamp, context);
session_pre_key_bundle_create(&bob_bundle, ...);
```

**Bước 4 — Alice thực hiện X3DH Handshake:**
```c
signal_protocol_address bob_address = { "+84900000002", 12, 1 };
session_builder_create(&alice_builder, alice_store, &bob_address, context);
session_builder_process_pre_key_bundle(alice_builder, bob_bundle);
/* Nội bộ: xác minh chữ ký SPK, tính DH1..DH4, khởi tạo Double Ratchet */
```

**Bước 5 — Alice mã hóa tin nhắn đầu tiên:**
```c
session_cipher_create(&alice_cipher, alice_store, &bob_address, context);
session_cipher_encrypt(alice_cipher, plaintext, strlen(plaintext), &encrypted_msg);
/* Kết quả: CIPHERTEXT_PREKEY_TYPE — chứa cả header X3DH + ciphertext */
```

**Bước 6 — Bob giải mã (thực hiện X3DH phía Bob + giải mã Double Ratchet):**
```c
session_cipher_create(&bob_cipher, bob_store, &alice_address, context);
pre_key_signal_message_deserialize(&pre_key_msg, serialized_data, len, context);
session_cipher_decrypt_pre_key_signal_message(bob_cipher, pre_key_msg, NULL, &decrypted_buf);
/* Bob tự động: xác thực X3DH, thiết lập Double Ratchet, giải mã AES-CBC, xóa OPK đã dùng */
```

---

## 3.15. Tổng kết kiến trúc và đặc điểm kỹ thuật

### 3.15.1. Kiến trúc phân lớp

```
┌────────────────────────────────────────────────────┐
│          Ứng dụng người dùng (App Layer)           │
├──────────────┬─────────────────┬───────────────────┤
│  Session     │  Group          │  Fingerprint /    │
│  Cipher      │  Cipher         │  Device Consistency│
├──────────────┴─────────────────┴───────────────────┤
│       Session Builder + Session State/Record       │
├──────────────────────────────────────────────────── ┤
│         Double Ratchet (ratchet.h/.c)              │
├──────────────────┬─────────────────────────────────┤
│   HKDF           │   Curve25519 (ECDH + Signature) │
├──────────────────┴─────────────────────────────────┤
│   Crypto Provider Callbacks (AES, HMAC, SHA, RNG)  │
└────────────────────────────────────────────────────┘
```

### 3.15.2. Các thuộc tính bảo mật được hiện thực

| Thuộc tính | Cơ chế hiện thực |
|-----------|-----------------|
| **Bảo mật tiến (Forward Secrecy)** | Vòng xoay DH Ratchet với cặp khóa ephemeral mới sau mỗi chu kỳ gửi/nhận |
| **Bảo mật tương lai (Break-in Recovery)** | KDF Ratchet đối xứng với seed 0x01/0x02; trạng thái tiến không thể đảo ngược |
| **Xác thực bản tin** | HMAC-SHA256 với `mac_key` riêng cho từng tin nhắn |
| **Từ chối chối bỏ (Deniability)** | X3DH sử dụng khóa tạm thời — không để lại bằng chứng ký có thể kiểm chứng |
| **Chống replay** | Phát hiện `SG_ERR_DUPLICATE_MESSAGE` qua kiểm tra counter |
| **Chống tin nhắn ngoài thứ tự** | Lưu trữ skipped message keys tạm thời trong session state |
| **Đệm bảo vệ kích thước** | API chấp nhận `padded_message` — khuyến khích ứng dụng đệm về kích thước cố định |
| **Xóa bộ nhớ an toàn** | `signal_explicit_bzero()` trên khóa bí mật trước khi giải phóng |

### 3.15.3. Nhận xét về chất lượng mã nguồn

Mã nguồn `libsignal-protocol-c` thể hiện chất lượng kỹ thuật cao:
- **Quản lý bộ nhớ nghiêm ngặt**: đếm tham chiếu + xóa dữ liệu nhạy cảm bằng `bzero`.
- **Kiểm tra lỗi toàn diện**: mọi lời gọi hàm đều được kiểm tra giá trị trả về; sử dụng nhãn `goto complete` để đảm bảo cleanup ngay cả khi xảy ra lỗi.
- **Kiến trúc plugin**: nhà cung cấp mật mã và cửa hàng lưu trữ đều là callback, dễ tích hợp vào bất kỳ nền tảng nào.
- **Tách biệt mối quan tâm**: mỗi module chỉ phụ trách một chức năng cụ thể; không có sự phụ thuộc vòng.
- **Bộ kiểm thử bao phủ rộng**: 17 tệp kiểm thử với tổng cộng hơn 350 KB mã, bao gồm cả các kịch bản biên (edge cases) như gửi đồng thời, tin nhắn ngoài thứ tự, và phục hồi phiên.

---

*Kết thúc Chương 3*
