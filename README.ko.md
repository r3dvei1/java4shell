# java4shell - CVE-2026-114938 분석·재현 키트

English: [README.md](README.md)

> **이름에 대해.** "Java4Shell"은 보안 업계가 이 취약점에 붙인 별명입니다(Oligo의 글
> "Java4shell explained"). 이 저장소의 능력 주장이 아닙니다. 이 키트는 **셸을 만들어내지
> 않습니다.** 결함 위치를 특정하고, 취약 경로까지 도달하며, 힙 손상을 재현하고, 대상
> 호스트가 노출됐는지 판별합니다. 원격 실행으로 확장하려던 시도와 그 실패 이유는
> [docs/lab-stack.md](docs/lab-stack.md)에 기록되어 있습니다.

OpenJDK **AVX-512 Base64 디코드 인트린직**의 힙 오버플로인
**CVE-2026-114938**("Java4Shell")에 대한 독립 분석, 도달성 하니스, 환경 게이트 도구입니다.

> 상태: **분석 + 재현 키트.** 힙 덮어쓰기는 재현됩니다. 실제 AVX-512 호스트에서 공개된
> 영향 빌드(`21.0.13.0.3`)를 실행하면 조작된 입력이 힙을 손상시켜 **4회 중 3회** JVM이
> 종료되고, `-XX:-UseBASE64Intrinsics`를 주면 사라집니다. 인접 객체의 length·klass 오염은
> **6/6 결정적**으로 재현됩니다. 무기화된 RCE 체인은 포함되어 있지 않습니다. 참고:
> [docs/results.md](docs/results.md), [docs/lab-report.md](docs/lab-report.md),
> [docs/lab-stack.md](docs/lab-stack.md).

> **정정 (2026-11-18).** 이 문서의 이전 판은 트리거를 "128바이트 초과"로 적었습니다.
> 공개된 트리거는 21/25/27에서 `"A"×64 + "="` (**65바이트**), 17에서는 `"A"×128 + "="`
> (129바이트)입니다. 발견자(Calif.io)는 Keycloak·Jira·Confluence·Jenkins·Artifactory·
> PingFederate에 대해 **사전 인증 RCE**를 시연했습니다. **9.2는 발견자의 CVSS 4.0 점수,
> 8.1은 Oracle의 CVSS 3.1 점수**이며 둘 다 사실입니다. 상세:
> [docs/correction-2026-11-18.md](docs/correction-2026-11-18.md)

---

## 요약

| | |
|---|---|
| 구성 요소 | `hotspot/compiler` - AVX-512 VBMI Base64 **디코드 스텁** |
| CWE | CWE-122 (힙 기반 버퍼 오버플로) |
| CVSS 3.1 | 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` (AC:H = 익스플로잇 난이도 높음) |
| 영향 빌드 | 17.0.21.0.3, 21.0.13.0.3, 25.0.5.0.3, 27.0.1.0.3 (+ GraalVM 해당판) |
| 수정 빌드 | 17u `jdk-17.0.21.1` 이후 아웃오브사이클 빌드 (8u·11u는 영향 없음) |
| 업스트림 픽스 | `8393212: Base64 optimization improvements` - `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp` **4줄** |
| 하드웨어 게이트 | CPU가 `avx512vbmi`와 `avx512bw`를 노출하고, JVM이 `UseAVX=3`, `UseBASE64Intrinsics=true`여야 함 |
| 도달 조건 | 128바이트 초과 Base64를 MIME 아닌 디코더로 한 번에 디코드 |

## 결함 요약

`generate_base64_decodeBlock()`은 `length > 128`이고 `isMIME == 0`일 때 벡터 경로로
진입합니다. 256/64바이트 블록 루프를 돈 뒤 `L_finalBit`에 1~63바이트가 남는데, 여기서
`output_size = (length / 4) * 3`으로 스토어 마스크를 계산합니다. 픽스 이전에는 **4글자
아톰보다 짧은 패딩 꼬리**(예: 130바이트 입력이 `==`로 끝나 2바이트 꼬리가 남는 경우)에서도
이 코드가 실행되어 `output_size`가 `0 - 1 - 1 = -2`가 되고, 마스크 시프트가 "전부 1"이
되어 목적지 배열 뒤로 **64바이트 벡터 스토어**가 나갑니다. Java는 이후 프레이밍 검사에서
`IllegalArgumentException`("wrong 4-byte ending unit")을 던지므로 손상은 조용히 지나갑니다.

픽스는 꼬리 경로 맨 앞에 다음을 추가합니다.

```c
__ BIND(L_finalBit);
// A padded Base64 tail shorter than one complete block is handled by Java.
__ cmpl(length, 4);
__ jcc(Assembler::less, L_bruteForce);
```

## 빠른 시작

```bash
# 0) 이 호스트가 공격 대상인지 먼저 확인 (exit 1 = 노출, 0 = 안전, 2 = 판정 불가)
bash tools/check-target.sh

# 1) 이 호스트가 취약 경로를 실행할 수 있는 환경인지
bash tools/gate.sh

# 2) 취약 디코드 경로 구동 (크래시가 없는 것이 정상 결과)
java src/Base64Trigger.java 100000

# 3) 대조군: 스칼라 경로로 같은 입력
java -XX:-UseBASE64Intrinsics src/Base64Trigger.java 100000
```

### 단일 진입점

```bash
./java4shell gate                      # 호스트의 모든 JDK에 대한 하드웨어·JVM 게이트
./java4shell selftest 100000           # 로컬 도달성 드라이버
./java4shell probe --url URL --mode auth    # 원격 도달성 프로브
./java4shell --target URL --param b --attempts 5000   # 원격 트리거 실행
./java4shell serve 8080                # 로컬 데모 디코드 서비스
```

요구 사항: `bash`, 그리고 `PATH`에 JDK가 있거나 Docker. Docker 폴백을 쓰면 런처가
`eclipse-temurin:17.0.21_9-jdk`를 사용하며, 이때 호스트에 바인딩된 대상은 `127.0.0.1`
대신 `host.docker.internal`로 접근해야 합니다.

**`./java4shell https://target` 같은 공격 명령은 없습니다.** 이 키트에는 원격 익스플로잇이
없습니다. 프리미티브는 x86 인트린직의 조용한 64바이트 힙 덮어쓰기이고, 동작하는 체인에는
힙 그루밍이 필요하며, 원격 도달에는 대상이 공격자 제어 Base64(128바이트 초과, 잘못된 패딩
꼬리)를 디코더로 넘겨야 합니다. `probe` 서브커맨드는 애플리케이션이 우리 입력을 디코드하는지
여부만 알려주며, 패치된 JVM과 미패치 JVM이 동일하게 응답하므로 둘을 구별하지 못합니다.

`tools/gate.sh`는 호스트의 JDK마다 다음을 출력합니다.

```
avx512vbmi: present|absent
UseAVX=3  UseBASE64Intrinsics=true
=> Base64/AVX-512 path: ACTIVE | inactive
```

`avx512vbmi`가 없으면 스텁이 **생성되지 않으므로** JDK 버전과 무관하게 이 취약점은
트리거될 수 없습니다.

## 저장소 구성

```
src/Base64Trigger.java      도달성 드라이버 (조작된 길이, 결과 집계)
src/RemoteAttack.java       원격 트리거 하니스 (--target, 상태·지연·크래시 흔적)
src/RemoteProbe.java        원격 도달성 프로브 (auth/query/body)
src/DecodeServer.java       로컬 데모 디코드 서비스 (검증 없는 Base64 디코드)
tools/gate.sh               호스트의 모든 JDK에 대한 CPU/JVM 게이트 검사
tools/onboard.sh            호스트 리포트 일괄 생성
lab-stack/                  nginx -> Tomcat 배포와 캠페인 스크립트
research/                   인접 객체 오염 계측(Groom, Groom2), OOB 프로브
results/                    재현 기록과 크래시 발췌
docs/analysis.md            코드 수준 원인 분석과 정확한 픽스
docs/results.md             측정값과 "증명된 것 / 아닌 것"
docs/lab-report.md          실제 AVX-512 호스트 계측 결과
docs/lab-stack.md           nginx -> Tomcat 144만 요청 캠페인 결과
docs/detection.md           탐지·인벤토리·완화 지침
docs/naming.md              이름은 CVE 별명이며 능력 주장이 아님
```

## 여기에 없는 것

* 힙 그루밍, 제어 흐름 탈취, 셸코드가 없습니다. `byte[]` 뒤로 나가는 64바이트 덮어쓰기는
  프리미티브이지 익스플로잇이 아닙니다.
* 공격자 경로가 자동이라고 주장하지 않습니다. `AC:H`는 실제입니다. 서버 코드가 공격자 제어
  Base64(128바이트 초과, MIME 아님)를 디코더에 넣어야 하고, 목적지가 손상시킬 가치가 있는
  객체와 인접해야 합니다.

## 참고 자료

* Oracle 공지: <https://www.oracle.com/security-alerts/cspunov2026.html>
* OpenJDK 취약점 어드바이저리 2026/11/17: <https://openjdk.org/groups/vulnerability/advisories/2026-11-17>
* CVE 레코드: <https://www.cve.org/CVERecord?id=CVE-2026-114938>
* 업스트림 커밋(17u): `8ea73158afc9f2c62f72df68beb8723032bf695e` - `8393212: Base64 optimization improvements`

## 라이선스

MIT - [LICENSE](LICENSE) 참조. 소유하거나 테스트 권한을 받은 시스템에만 사용하십시오.
