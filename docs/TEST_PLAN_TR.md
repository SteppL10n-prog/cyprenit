# Cyprenit Engine v1.0.0-Beta — Layer 4: Async eBPF Pasif Keşif Prototipi
## Kritik Unit Test Planı

**Tehdit modeli:** Bu prototip kurumsal altyapı veri merkezinde *non-invasive* çalışır.
En büyük iki üretim riski:
1. **Deadlock / performans kilitlenmesi:** Kernel→User-space ring buffer aktarımında
   consumer bloke olursa producer (eBPF `bpf_ringbuf_output`) kernel yolunu tıkar;
   TLS el sıkışma gecikmeleri (handshake latency) artar → ağ trafiği kesintiye uğrar.
   Ayrıca parser goroutine'i bir paket işlerken panic yaparsa kanal kapanır ve tüm
   pipeline kilitlenir.
2. **Bellek sızıntısı:** Ring kayıtlarının (`[]byte`) veya çıkarılan kayıt yapılarının
   (`ParsedRecord`) serbest bırakılmaması, uzun ömürlü daemon'da RSS'in lineer büyümesine
   yol açar.

Bu yüzden aşağıdaki **5 kritik senaryo**, implementasyondan ÖNCE sözleşme (contract)
olarak yazılmıştır ve `go test` ile doğrulanır.

---

### TEST-01 — Ring Buffer Consumer Deadlock Yok (Backpressure / Non-blocking Producer)
**Amaç:** Producer hiç bloklamamalı; consumer yavaşsa kayıt düşer ama sistem kilitlenmez.
**Adımlar:**
- Pipeline'ı 10 OKB'lik halkalarla başlat (kapasite = 8192 bayt → ~2 kayıt sığar).
- 10.000 kaydı eşzamanlı olarak 50 producer goroutine ile gönder.
- Consumer'ı hiç okuma (en kötü durum: kullanıcı alanı askıda).
**Kabul Kriterleri:**
- `Submit()` hiçbir koşulda bloklamaz; tamamı < 5 sn içinde döner.
- Overflow sayacı == tam olarak beklenen drop sayısı (sessiz kayıp YOK, ölçülebilir kayıp VAR).
- `Close()` deadlock'suz ≤ 5 sn içinde döner (goroutine sızıntısı da burada yakalanır:
  kapanışta aktif goroutine sayısı taban çizgisine dönmeli).
**Kernel karşılığı:** `BPF_RB_NO_WAKEUP` + user tarafında ayrı reader goroutine'i;
ring doluysa `bpf_ringbuf_output` `NULL` döner → drop sayacı artırılır, paket yolu asla durmaz.

### TEST-02 — Bellek Sızıntısı: ParsedRecord Havuzu Kayıt Başına Tam Geri Verilmeli
**Amaç:** Havuzdan (sync.Pool benzeri object pool) alınan her yapı geri verilmeli;
kapanışta havuz dışına taşma (leak) olmamalı.
**Adımlar:**
- 10.000 sahte TLS ClientHello kaydını parse et → `ParsedRecord` al → tüket → `Release()`.
- Pool'un "alınmış" sayaçlarını kontrol et.
**Kabul Kriterleri:**
- `InUse() == 0`, `Leaked() == 0`, `Peak() <= 2*numCPU` (yalnızca worker başına geçici kayıt).
- Release edilmemiş 100 kayıt simüle edildiğinde `Leaked() == 100` (test, gözüm kör değil:
  leak dedektörü gerçekten çalışmalı).

### TEST-03 — TLS Handshake Parser: Algoritma Tespiti (RSA / ECC / Fallback SBC / ML-KEM / Hybrid)
**Amaç:** PQC risk haritasının çekirdeği — doğru şifre suite tespiti.
**Girdiler (gerçek RFC 8446 wire format):**
- ClientHello #1: `TLS_RSA_WITH_AES_128_GCM_SHA256 (0x002C)` + legacy_session_id → `rsa_kx`
- ClientHello #2: `TLS_AES_128_GCM_SHA256 (0x1301)` + `key_share` uzantısında
  `X25519 (0x001D)` → `ecc_x25519`
- ClientHello #3: `key_share`'de `codepoint 4588 (0x11DC)` → `mlkem768_pqc`
- ClientHello #4: hem X25519 hem 4588 → `hybrid_x25519_mlkem768`
- Case-fuzz: aynı girdinin byte-swapped / kırpılmış versiyonları → `unknown`, ASLA panic yok.
**Kabul Kriterleri:** 4 pozitif tespit + malformed girdilerde graceful fallback;
`detectPQRisk()` sıralaması: `rsa_kx > ecc > hybrid > pure-PQC` (risk puanı 100..10).

### TEST-04 — Kernel/User Wire Format Uyumu (ABI): Go binary ↔ eBPF C Yapısı
**Amaç:** Ring buffer'dan gelen ham baytların C tarafındaki `struct cyprenit_evt` ile
birebir aynı olduğunu garanti etmek (yanlış offset = bozuk harita = sessiz veri kaybı).
**Adımlar:**
- Referans kayıt sabitleriyle encode et → hex sabitle karşılaştır (golden vector).
- Decode et → round-trip equality.
- `unsafe.Sizeof` yerine sabit `EventSize = 128` kullanımı doğrula; kısa/uzun tampon
  decode'unda hata dön, panic dönme.
**Kabul Kriterleri:** Golden hex vektörü sabit; `binary.Size(struct)` testi derleme
sırasında ABI regresyonunu kırar.

### TEST-05 — Concurrent Stress & Graceful Shutdown (Panic Isolasyonu)
**Amaç:** 1000 event × 8 worker; bir worker panikse bile diğerleri çalışmaya devam etsin,
Close() sonradan gelen Submit'leri reddetsin, çift Close() idempotent olsun.
**Adımlar:**
- Stress koş; ortada `Stop()` çağır; sonra yeni `Submit()` dene.
- Bilerek poison (panic tetikleyen) payload enjekte et.
**Kabul Kriterleri:**
- Poison kayıt `ErrPoison` olarak raporlanır, worker ölmez (recover sarımı).
- `Stop()` sonrası `Submit()` → `ErrClosed`, blokaj yok.
- Çift `Close()` panic/hata üretmez. Tüm testler `-race` ile yeşil.

---

## Çalıştırma
```bash
cd cyprenit
go test ./... -race -count=1        # 5 kritik senaryo + ek birim testleri
```
> Not: eBPF programının (`tls_probe.bpf.c`) yüklenmesi root + BTF'li ≥5.8 kernel ister.
> CI konteynerinde (kernel 4.19) loader'ı "dry-run" modda çalıştırıyoruz; bu nedenle
> yukarıdaki unit testler kernel'e bağımlı DEĞİLDİR — parser, ring ve ABI izole edilir.
