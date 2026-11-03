# Cyprenit Engine v1.0.0-Beta — Kali Linux Kullanım Kılavuzu (Adım Adım)

**Layer 4: Async eBPF Pasif Keşif Prototipi — PQC Risk Haritası**

Bu kılavuz, `cyprenit-async` aracını Kali Linux terminalinde kurmanız, çalıştırmanız,
neyi nereye araştıracağını anlamanız ve Cyprenit uyum (DORA/ISO 27001) uyumlu denetim raporu
üretmeniz için adım adım rehberdir.

---

## 0. Mimari Özet — "Neyi, Nerede Araştırıyor?"

```
[Ağ Paketi]                                                     [Rapor]
     |                                                             ^
     v                                                             |
Kernel: socket_filter (ebpf/tls_probe.bpf.o)              internal/metrics/reporter.go
     |  TLS ClientHello'yu pasif dinler                     DORA Md.9&12 / ISO A.8.24
     v                                                     Markdown audit.md üretir
eBPF Ring Buffer (8 MB, async, kesintisiz)
     |
     v
User-Space Go servisi (cmd/cyprenit-async/main.go)
  ├─ internal/ring/pipeline.go   : asenkron pipeline (4 parse worker, drain-then-close)
  ├─ internal/parser/pool.go     : RecordPool (mutex-altı epoch + atomic sayaçlar)
  ├─ internal/parser/parser.go   : cipher-suite sınıflandırma (RSA/ECC/Hybrid/PurePQC)
  ├─ internal/metrics/riskmap.go : akış bazlı risk haritası (skor 0-100)
  └─ internal/abi                : kernel<->user sabit 128 bayt ABI sözleşmesi
```

**Ne araştırılır:** TCP 443 (ve `-ports` ile genişletilen) portlardaki TLS handshake
paketleri içindeki **cipher suite listesi** ve **supported_groups / key_share**
uzantıları. Buradan sunucunun hangi kriptografiyi kullandığı çıkarılır:

| Tespit | Anlam | Risk Skoru |
|---|---|---|
| RSA key exchange / CBC suite'ler | PQC yok, klasik RSA | 100 = CRITICAL |
| ECDHE (X25519/P-256) | ECC, harvest-now-decrypt-later'a açık | 70 = HIGH |
| ML-KEM / X25519MLKEM768 hibrit | Geçiş aşaması | 30 = MEDIUM |
| Saf PQC suite (ML-KEM only) | Post-kuantum hazır | 0 = LOW |

**Non-invasive prensip:** Paketlere dokunulmaz, bağlantı kesilmez, sadece gözlenir.
Ring buffer dolarsa olay düşer ama uygulama bloklanmaz (drop sayacı rapora işlenir).

---

## 1. Hazırlık — Sistem Gereksinimleri (Kali)

Canlı eBPF modu için:

```bash
# Kernel sürümü >= 5.18 önerilir (Kali rolling zaten uygundur)
uname -r

# Root yetkisi gerekli (eBPF program yüklemek için)
sudo -v
```

Araç kurulumları:

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
     bpftool golang-go tcpdump openssl ca-certificates
go version    # >= 1.21 olmalı
```

> **Not:** Repo ile gelen `ebpf/tls_probe.bpf.o` hedef makinenin header'larıyla
> üretilmemiş olabilir; Bölüm 3'te Kali'de yeniden derleyeceğiz.

---

## 2. Projeyi Kali'ye Taşıma / Derleme

Projeyi ZIP/Git ile Kali'ye aldıktan sonra:

```bash
cd cyprenit

# Go kullanıcı alanı — derleme + testler (eBPF gerektirmez, her ortamda koşar)
gofmt -l .
go build ./... && go vet ./...
go test -race -count=1 ./...        # TEST-01..05 hepsi PASS olmalı

# CLI binary
go build -o bin/cyprenit-async ./cmd/cyprenit-async
./bin/cyprenit-async -h               # bayrakları gör
```

### (İsteğe bağlı) eBPF nesnesini Kali'de yeniden derleme

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/usr/include/$(uname -m)-linux-gnu \
      -c ebpf/tls_probe.bpf.c -o ebpf/tls_probe.bpf.o
bpftool gen object tls_probe.skel.o ebpf/tls_probe.bpf.o   # opsiyonel iskelet
ls -la ebpf/tls_probe.bpf.o
```

---

## 3. Çalıştırma Modları

Aracın üç çalışma modu vardır. İlk iki mod root/kernel eBPF **gerektirmez** —
denemeye oradan başlayın.

### MOD A — `-dry-run` (Sentetik telemetri, eBPF'sız uçtan uca deneme)

Amacı: pipeline, havuz, sınıflandırıcı ve rapor motorunu canlı ağ olmadan test etmek.

```bash
mkdir -p ~/cyprenit-out
./bin/cyprenit-async -dry-run -duration 8s -report 2s -out ~/cyprenit-out/audit-dry.md

# Çıktıyı izle
cat ~/cyprenit-out/audit-dry.md
```

Başarı ölçütleri (terminal çıktısında arayın):
- `pool in-use=0` → bellek sızıntısı yok (TEST-02 davranışı canlıda da doğru)
- `drops=0` veya düşük → backpressure yok
- kapanışta `shutdown clean` benzeri satır → deadlock yok (TEST-01/05)

### MOD B — `-pcap` (Kayıtlı trafiği yeniden oynatma — gerçek tespit denemesi)

Gerçek TLS handshake'lerle sınıflandırıcıyı doğrulamak için en güvenli yol.

```bash
# 1) Hedefinizden bir pcap alın (veya laboratuvarda kendiniz üretin):
#    Aşağıdaki komut size SADECE kendi ağınıza ait örnek TLS trafiği üretir:
sudo tcpdump -i any -w lab.pcap 'tcp port 443 and (tcp[((tcp[12:1] & 0xf0) >> 2):2] == 0x16)' &
DPID=$!
sleep 2
# Birkaç gerçek TLS oturumu tetikle:
openssl s_client -connect one.one.one.one:443 </dev/null 2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect www.google.com:443 </dev/null 2>/dev/null | grep -E "Protocol|Cipher"
sleep 2; sudo kill $DPID; wait $DPID 2>/dev/null

# 2) Cyprenit ile pcap'i analiz et:
sudo ./bin/cyprenit-async -pcap lab.pcap -report 2s -out ~/cyprenit-out/audit-pcap.md
cat ~/cyprenit-out/audit-pcap.md
```

Doğrulama: `grep Cipher` çıktısındaki suite (ör. `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`) rapor tablosunda **doğru risk sınıfına**
atanmış olmalı (ECDHE+AES-GCM → ECC sınıfı, HIGH RISK; RSA-kex → CRITICAL).

### MOD C — Canlı eBPF pasif keşif (asıl kullanım)

Kurumsal veri merkezi senaryosu: sunucunun ağ trafiğini **kesmeden** dinler.

```bash
# 1) İzlenecek arayüzün ifindex'ini bul:
ip link show
#   örn: 2: eth0: <...>  => ifindex = 2

# 2) Başlat (tüm arayüzler için -ifindex 0):
sudo ./bin/cyprenit-async \
     -ifindex 0 \
     -report 10s \
     -out /var/log/cyprenit_audit.md

# 3) Aynı terminal dışında trafiği kışkırt (test amaçlı):
watch -n 5 'curl -sv https://www.example.com -o /dev/null 2>&1 | grep -E "SSL connection|Cipher"'

# 4) Süre sonunda veya Ctrl-C ile durdur; kapanış loglarını kontrol et:
#    pool in-use=0, drops=sabit, goroutine sızıntısı yok
```

Sinyal ile düzgün kapatma (SIGTERM = graceful shutdown, drain-then-close):

```bash
sudo pkill -TERM -f cyprenit-async
```

---

## 4. Neyi, Nereye, Nasıl Araştırır? (Operasyonel Checklist)

Denetimde sırayla şunlara bakın:

1. **Kimlik doğrulama:** `sudo ./bin/cyprenit-async ...` satırında `-out` verilen dosya
   gerçekten yazılıyor mu? (`ls -la /var/log/cyprenit_audit.md`)
2. **Envanter:** Rapordaki tablo satırları = tespit edilen akışlar.
   Alanlar: `Network (srcIP→dstIP), Port, AlgorithmClass, RiskScore, PriorityLabel`.
3. **En kritik bulgu filtresi:**
   ```bash
   grep -E "CRITICAL|ACİL" ~/cyprenit-out/*.md
   ```
   → RSA key-exchange kullanan sunucular = göç planında 1. öncelik.
4. **Hibrit/geçiş izleme:**
   ```bash
   grep -E "Hybrid|MEDIUM" ~/cyprenit-out/*.md
   ```
   → ML-KEM hibrit kullanıp henüz saf PQC'ye geçmemiş sistemler (DORA Md.12 için takip maddesi).
5. **Veri bütünlüğü:** Terminal logunda `drops` ve `overflow` sayaçları.
   Yüksek drop → `-queue-depth 8192` artırın veya `-workers 8` yapın.
6. **Sızıntı denetimi:** Her kapanışta `pool in-use` değeri. Sıfır değilse
   kaçak kayıt var demektir → `go test -race -run TestLeakDetector ./internal/...` ile yeniden üretin.
7. **Yetkisizlik hatası:** `Operation not permitted` → root değilsiniz veya
   kernel lockdown/BPF kısıtı var:
   ```bash
   sudo sysctl kernel.unprivileged_bpf_disabled=0   # geçici; denetim sonrası geri alın
   ```
8. **Yanlış interface:** Hiç akış görünmüyorsa `ip addr` ile doğru `-ifindex`
   verildiğinden emin olun; VLAN/bonding'de fiziksel parent'ı izleyin.

---

## 5. Rapor Çıktısı — Nasıl Görür, Nasıl Paylaşır?

`-out` ile üretilen Markdown, denetim standartlarına göre 3 bölümlüdür:

- **Başlık özeti:** MaxRisk alanı (CRITICAL / ACİL MÜDAHALE, HIGH RİSK, MEDIUM, LOW, NONE)
- **Akış tablosu:** yukarıdaki 5 sütun
- **Standart referans bloğu:** DORA Madde 9 & 12, ISO/IEC 27001:2022 A.8.24

Okuma/dağıtım:

```bash
glow ~/cyprenit-out/audit-pcap.md          # terminalde renkli görüntüle (apt install glow)
pandoc ~/cyprenit-out/audit.md -o audit.pdf  # PDF'e çevir, yönetime gönder
```

---

## 6. Sık Karşılaşılan Sorunlar (Troubleshooting)

| Belirti | Neden | Çözüm |
|---|---|---|
| `failed to load BPF object` | `.o` hedef kernel için üretilmemiş | Bölüm 2'deki `clang` adımıyla Kali'de yeniden derleyin |
| `RTNETLINK answers: Operation not supported` | TC/socket attach kısıtı | Root + `-ifindex` spesifik arayüz deneyin |
| Rapor boş (`NONE`) | İzlenen yolda TLS yok / yanlış ifindex | `ip link`, `tcpdump -i any port 443` ile trafiği önce siz görün |
| `drops` artıyor | Queue doygunluğu | `-queue-depth 16384 -workers 8` |
| Kapanış takılıyor | (v1.0.0-Beta'te giderildi: drain-then-close) | Yine olursa `sudo pkill -INT` + issue kaydı |
| `-race` testi FAIL (geliştirici) | ABI/sayaç regresyonu | `go test -race -count=5 ./internal/...` ile daraltın |

---

## 7. Güvenli İmha / Kapatma Protokolü (Denetim Sonu)

```bash
# 1) Süreç düzgün kapatıldı mı?
pgrep -fa cyprenit-async || echo "kapandı"

# 2) Kalıntı BPF program/map var mı?
sudo bpftool prog list | grep -i tls
sudo bpftool map list  | grep -i ring
# Varsa ID ile temizle: sudo bpftool prog delete id <ID>

# 3) Ham veri politikası: pcap ve audit dosyalarını şifreli arşive taşıyin
shred -u lab.pcap            # ham paket yakalini imha et (genel veri saklama politikasi)
```

---

## 7b. Doğrulanmış Örnek Çıktı (bu repoda `-race` testleriyle birlikte üretilmiştir)

`-dry-run` modunun gerçek çıktısı — aşağıdaki değerleri kendi koşunuzda da görün:

```
== Cyprenit PQC Risk Haritası == submitted=2 overflow=0 parsed=2 emitted=2 panics=0
  [CRITICAL] 10.0.4.250:443 rsa_kx=1 ecc=0 hybrid=0 pqc=0 unknown=1
kapanış: pool in-use=0 peak=1 gets=2 puts=2 (in-use MUST be 0)
denetim raporu yazıldı: /tmp/audit-dry.md
```

Üretilen `audit-dry.md`:

```markdown
# Cyprenit Engine v1.0.0-Beta PQC Risk Raporu
Standart Referanslari: DORA Madde 9 & 12 | ISO/IEC 27001:2022 A.8.24
Maksimum Risk Seviyesi: CRITICAL / ACİL MÜDAHALE

| Ag | Port | Algoritma Sinifi | Risk Skoru | Oncelik |
|----|------|------------------|------------|---------|
| 10.0.4.250 | 443 | RSA-KX | 100 | CRITICAL |
```

Ödeme kıstasları: `overflow=0`, `panics=0`, kapanışta `pool in-use=0`.

---

## 8. Hızlı Referans — Bayraklar

| Bayrak | Varsayılan | Açıklama |
|---|---|---|
| `-dry-run` | false | eBPF'sız sentetik uçtan uca çalıştırma |
| `-pcap <dosya>` | "" | Canlı yerine pcap yeniden oynatma |
| `-ifindex <n>` | 0 | İzlenecek arayüz (0 = tümü) |
| `-report <süre>` | 10s | Risk haritası yazım aralığı |
| `-out <dosya>` | "" | Kapanışta Markdown denetim raporu yolu |
| `-duration <süre>` | 0 | 0 = sürekli; >0 = şu sürede graceful kapan |
| `-workers <n>` | 4 | Parse worker sayısı (doygunlukta artır) |
| `-queue-depth <n>` | 4096 | Bounded queue; dolu ⇒ drop + sayaç |

---

*Cyprenit Engine v1.0.0-Beta Layer 4 — pasif, kesintisiz, kanıtlanabilir. Tüm değişikliklerde
bölüm 2'nin test komutlarını tekrar koşun; yeşil olmayan build'i üretime almayın.*
