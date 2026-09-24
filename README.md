# Remote Attestation SIMPLE — Verifier / Gateway / Prover testbed

An adapted prototype of the **SIMPLE** remote attestation protocol from Ammar et al.,
*"SIMPLE — A Remote Attestation Approach for Resource-constrained IoT devices"*.
It implements an authenticated challenge–response attestation workflow with
profile-dependent memory measurement on a three-node architecture composed of a
PC verifier, an ESP32 Wi-Fi/UART gateway, and an STM32 Nucleo-H503RB prover.

Course project — *Cyber-Physical Systems and IoT Security*, University of Padua.

> **Scope / disclaimer.** This is a laboratory proof of concept.
> The prototype preserves the core verifier–prover attestation logic of SIMPLE but
> differs from the original design in hardware platform, communication architecture,
> and trusted-computing assumptions (STM32 MPU/GTZC isolation instead of SμV-based
> software isolation). Cryptographic keys are statically embedded; no secure
> provisioning is implemented. See the report for a full discussion of deviations.

---

## What it does

A PC, an ESP32, and an STM32 board form the attestation system:

- **verifier** (PC) — Python CLI that generates authenticated attestation requests,
  sends them over Wi-Fi/TCP to the gateway, validates the prover's authenticated
  response, and maintains persistent state (counters, expected valid-state baselines)
  in a local JSON file.
- **gateway** (ESP32) — lightweight TCP↔UART bridge implemented with ESP-IDF.
  Exposes a Wi-Fi access point (`RemoteAttestationAP`) and transparently relays
  protocol frames between the verifier and the prover. It holds no cryptographic
  trust and does not parse attestation semantics.
- **prover** (STM32 Nucleo-H503RB) — firmware that receives attestation requests,
  verifies their MAC and freshness, computes a profile-dependent SHA-256/HMAC-SHA256
  measurement over selected memory regions, compares it against the verifier's
  expected value, and returns an authenticated response. The attestation logic runs
  inside a privileged SVC path protected by MPU and GTZC.

---

## Attestation profiles

| Profile | Label            | Measured regions                                         |
|---------|------------------|----------------------------------------------------------|
| 1       | `flash-only`     | main attested flash + privileged flash (attestation code & keys) |
| 2       | `flash+ram`      | Profile 1 + `.app_attested_ram` (application manifest)   |
| 3       | `flash+ram+cfg`  | Profile 2 + `.attest_cfg` (configuration shadow)         |

---

## Repository layout

```
.
├── prover/                 # STM32 firmware (Makefile-based build)
│   ├── Core/
│   │   ├── Inc/            # headers (attestation.h, protocol.h, …)
│   │   └── Src/            # sources (main.c, attestation.c, …)
│   ├── Drivers/
│   ├── Makefile
│   └── STM32H503RBTx.ld    # linker script
├── gateway/                # ESP32 ESP-IDF project
│   ├── main/
│   │   └── spp_main.c
|   ├── components/
│   │   ├── app_config/           
│   │   ├── tcp_bridge/            
│   │   ├── uart_bridge/           
│   │   └── wifi_ap/
|   ├── sdkconfig    
│   └── CMakeLists.txt
├── verifier/               # Python CLI package
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── client.py
│   ├── constants.py
│   ├── models.py
│   ├── state_store.py
│   ├── utils.py
│   ├── verifier.py
│   ├── wire.py
│   └── verifier/
│       └── verifier_state.json # auto-generated persistent state
└── README.md
```

---

## Hardware requirements

- 1 × STM32 Nucleo-H503RB (prover).
- 1 × ESP32 board (gateway) — any variant with Wi-Fi; default UART pins are
  TX=GPIO 17, RX=GPIO 16.
- 1 × PC with Wi-Fi (verifier).
- USB cables for flashing the STM32 (ST-Link / SWD) and ESP32.
- UART wiring between ESP32 and STM32.

### Wiring (ESP32 ↔ STM32)

| Signal   | ESP32 pin | STM32 pin         |
|----------|-----------|--------------------|
| UART TX  | GPIO 17   | USART RX           |
| UART RX  | GPIO 16   | USART TX           |
| GND      | GND       | GND                |

UART runs at 115200 baud, 8N1.

---

## Software requirements

**STM32 prover**
- `arm-none-eabi-gcc` toolchain
- `make`
- `STM32_Programmer_CLI` (or equivalent SWD flasher, note that in theory is also possible to use DFU but it is not already tested)

**ESP32 gateway**
- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/) installed and
  exported in the shell

**PC verifier**
- Python 3.10+
- No external pip dependencies (stdlib only)

---

## Build & flash the STM32 prover

```bash
cd prover
make clean
make
STM32_Programmer_CLI -c port=SWD -w build/prover.elf -v -rst
```

Artifacts are generated in `prover/build/` (`prover.elf`, `prover.hex`, `prover.bin`).

---

## Build & flash the ESP32 gateway

```bash
cd gateway
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

> Adjust `/dev/ttyUSB0` to match your board. The gateway starts a Wi-Fi AP
> immediately on boot.

Default gateway settings:

| Setting        | Value                  |
|----------------|------------------------|
| Wi-Fi SSID     | `RemoteAttestationAP`  |
| Wi-Fi password | `12345678`             |
| TCP port       | `8080`                 |
| UART baud      | `115200`               |
| UART TX / RX   | GPIO 17 / GPIO 16      |

---

## Run procedure

1. Flash the STM32 prover and the ESP32 gateway (sections above).
2. Power both boards; verify the ESP32 serial monitor shows the AP is up.
3. Connect the PC to the `RemoteAttestationAP` Wi-Fi network (password `12345678`).
4. Bootstrap the desired profile to learn the expected valid-state baseline:
   ```bash
   python3 -m verifier --profile 1 --bootstrap
   ```
5. Run a normal attestation:
   ```bash
   python3 -m verifier --profile 1
   ```
6. Repeat for Profiles 2 and 3 as needed.

The verifier prints the attestation outcome, e.g.:

```
Requesting attestation for profile 1 (flash-only)
counter=3
nonce=...
expected_vs=<hex>
[resp] counter=3 profile=1 result=0x00(SUCCESS) flags=0x01
Attestation OK.
```

---

## Verifier options (summary)

| Flag                  | Purpose                                           |
|-----------------------|---------------------------------------------------|
| `--profile {1,2,3}`  | **(required)** select attestation profile          |
| `--bootstrap`         | two-step enrollment of the expected valid state    |
| `--tcp HOST:PORT`     | override target (default `192.168.4.1:8080`)       |
| `--counter N`         | manually set the request counter (testing only)    |
| `--expected-vs-hex`   | override the stored expected VS with a hex value   |
| `--adopt-local-vs`    | store the prover's returned VS as the new baseline |
| `--state-file PATH`   | change the persistent-state JSON path              |
| `--no-state`          | disable state file (ephemeral mode)                |
| `--timeout SECONDS`   | TCP socket timeout (default 3.0)                   |
| `--fixed-nonce`       | use deterministic nonce `00..0f` (debugging)       |
| `--nonce-hex HEX`     | provide a fixed 16-byte nonce                      |

Full details: `python3 -m verifier --help`

---

## Results (this testbed)

| Test                             | Result                                                    |
|----------------------------------|-----------------------------------------------------------|
| Bootstrap & baseline enrollment  | all three profiles enrolled successfully                  |
| Benign attestation               | SUCCESS for all profiles against stored baseline          |
| Flash tampering detection        | detected by Profile 1 (and 2, 3)                         |
| RAM tampering detection          | detected by Profiles 2 and 3                              |
| Config tampering detection       | detected by Profile 3 only                                |
| Replay (stale counter)           | rejected with `STALE_COUNTER`                             |
| Prover crypto runtime            | 0.93–0.94 ms total privileged path (Profiles 1–3)        |
| End-to-end round trip            | ≈249–250 ms (dominated by Wi-Fi + UART + host latency)   |

See the report for full runtime tables and comparison with the original SIMPLE paper.

---

## Benchmarking

The firmware supports optional cycle-counter instrumentation for the runtime
tables in the report. Enable `ATTESTATION_BENCHMARK` in
`prover/Core/Inc/attestation.h`, rebuild and reflash, then run:

```bash
python3 -m verifier --profile 1 --repeat 100 --csv timings_profile1.csv
python3 -m verifier --profile 2 --repeat 100 --csv timings_profile2.csv
python3 -m verifier --profile 3 --repeat 100 --csv timings_profile3.csv
```

The verifier converts cycles to milliseconds using `--hclk-hz` (default `250000000`,
matching the current `SystemClock_Config()`). For a production build, set
`ATTESTATION_BENCHMARK` to `0u` and disable `ATTESTATION_INCLUDE_LOCAL_VS_DEBUG`.

---

## Notes & known limitations

- The verifier's bootstrap mode learns the expected valid state from the prover
  itself. This is convenient for lab use but weakens the trust model; a real
  deployment should provision the baseline through a trusted channel.
- Cryptographic keys (`K_AUTH`, `K_ATTEST`) are statically embedded in source.
  No hardware-backed key storage or secure provisioning is implemented.
- The debug build includes `local_vs` in every response; disable
  `ATTESTATION_INCLUDE_LOCAL_VS_DEBUG` for a hardened build.
- Exit codes: `0` success, `1` CLI error, `2` attestation failure,
  `3` stale counter, `4` other protocol/runtime failure.

---

## References

[1] M. Ammar, B. Crispo, B. Preneel, and W. Joosen,
*SIMPLE — A Remote Attestation Approach for Resource-constrained IoT devices*,
ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec), 2020.

[2] Espressif Systems,
*ESP-IDF Programming Guide*,
2024. Available: https://docs.espressif.com/projects/esp-idf/en/latest/
(Accessed: 2026-06-09).

[3] STMicroelectronics,
*NUCLEO-H503RB — STM32 Nucleo-64 development board*,
2024. Available: https://www.st.com/en/evaluation-tools/nucleo-h503rb.html
(Accessed: 2026-06-09).
